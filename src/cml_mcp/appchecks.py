"""Application-level probes run from a Linux node's console: `http` (curl, else wget) and `dns` (dig, else
drill, host or nslookup). They follow the CML Cookbook check types of the same names:

    probes:
      - {name: app-page, node: client1, http: {url: http://10.20.0.10/, expect: {pattern: Welcome}}}
      - {name: eicar-blocked, node: client1, http: {url: http://10.20.0.10/eicar.com,
         expect: {no_response: true}}}
      - {name: sinkholed, node: client1, dns: {name: bad.lab.example, server: 10.20.0.53,
         expect: {answers: [10.99.99.99], not_answers: [10.20.0.66]}}}

http passes when the status is in `status` (default any 2xx; redirects are not followed), `pattern` matches
the body and `not_pattern` doesn't; with `no_response` only when the connection is refused, reset or
times out.
dns passes when the response code is `rcode` (default NOERROR), every `answers` entry is in the answers
and no `not_answers` entry is (NOERROR with no `answers` needs at least one answer); with `no_response` only
when the query times out. Each probe is retried until it passes or its `timeout` (default 180 s) runs out.

The commands are built here from validated fields (never caller text), so they need no read-tier check.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cml_mcp.console import FORBIDDEN_CHARS, Credentials, mask_secrets
from cml_mcp.netops import Command, console_batch

if TYPE_CHECKING:
    from cml_mcp.client import CmlApp

DEFAULT_TIMEOUT = 180.0  # seconds a probe is retried, as in the Cookbook
TRY_SECONDS = 10  # one curl/wget attempt; one DNS query waits 3 s
RETRY_INTERVAL = 10.0
MAX_BODY = 65536  # bytes of body read back over the console
HTTP_TOOLS = ("curl", "wget")
DNS_TOOLS = ("dig", "drill", "host", "nslookup")
TOOLS_COMMAND = "command -v " + " ".join(HTTP_TOOLS + DNS_TOOLS)

URL = re.compile(r"^https?://[^\s'\"|]+$")
DNS_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")


def _regex(rx: str | None) -> None:
    if rx:
        try:
            re.compile(rx, re.M)
        except re.error as e:
            raise ValueError(f"bad regex {rx!r}: {e}") from e


class HttpExpect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: int | list[int] | None = None
    pattern: str | None = None
    not_pattern: str | None = None
    no_response: Literal[True] | None = None

    @model_validator(mode="after")
    def _check(self) -> HttpExpect:
        if self.no_response and (self.status is not None or self.pattern or self.not_pattern):
            raise ValueError("no_response can't be combined with status, pattern or not_pattern")
        codes = [self.status] if isinstance(self.status, int) else self.status or []
        if any(not 100 <= c <= 599 for c in codes):
            raise ValueError("status must be 100-599")
        _regex(self.pattern)
        _regex(self.not_pattern)
        return self

    def statuses(self) -> list[int] | None:
        return [self.status] if isinstance(self.status, int) else self.status


class HttpCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    method: Literal["GET", "HEAD", "POST"] = "GET"
    insecure: bool = False
    expect: HttpExpect = HttpExpect()

    @model_validator(mode="after")
    def _check(self) -> HttpCheck:
        if not URL.fullmatch(self.url) or any(ch in FORBIDDEN_CHARS for ch in self.url):
            raise ValueError(
                f"http url {self.url!r} must be http(s)://... without quotes, spaces or ; & ` $ < > \\"
            )
        return self


class DnsExpect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rcode: Literal["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"] = "NOERROR"
    answers: list[str] | None = None
    not_answers: list[str] | None = None
    no_response: Literal[True] | None = None

    @model_validator(mode="after")
    def _check(self) -> DnsExpect:
        if self.no_response and (self.answers or self.not_answers or "rcode" in self.model_fields_set):
            raise ValueError("no_response can't be combined with rcode, answers or not_answers")
        if self.answers and self.rcode != "NOERROR":
            raise ValueError("answers can only be expected with rcode NOERROR")
        return self


class DnsCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    record: Literal["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"] = "A"
    server: str | None = None
    expect: DnsExpect = DnsExpect()

    @model_validator(mode="after")
    def _check(self) -> DnsCheck:
        for what, v in (("name", self.name), ("server", self.server)):
            if v is not None and not DNS_NAME.fullmatch(v):
                raise ValueError(f"dns {what} {v!r} must be a host name or address")
        return self


# --- tools on the node ------------------------------------------------------------------------


def parse_tools(text: str) -> set[str]:
    """Tool names from `command -v ...` output (one path or builtin name per line)."""
    found = set()
    for line in text.splitlines():
        word = line.strip().rsplit("/", 1)[-1]
        if word in HTTP_TOOLS + DNS_TOOLS:
            found.add(word)
    return found


def pick(tools: set[str], wanted: tuple[str, ...]) -> str | None:
    return next((t for t in wanted if t in tools), None)


# --- http -------------------------------------------------------------------------------------


def http_command(tool: str, c: HttpCheck) -> str:
    """One request; the response (headers, then up to MAX_BODY bytes of body) on stdout. `awk 1` ends the
    output with a newline so the shell prompt starts its own line."""
    if tool == "curl":
        parts = ["curl -sS -g --max-time", str(TRY_SECONDS)]
        if c.insecure:
            parts.append("-k")
        if c.method == "HEAD":
            parts.append("-I")
        else:
            parts.append("-D -")
            if c.method == "POST":
                parts.append("-X POST --data ''")
    else:
        parts = [
            "wget -nv -S -O - --max-redirect=0 --tries=1 --content-on-error --timeout=" + str(TRY_SECONDS)
        ]
        if c.insecure:
            parts.append("--no-check-certificate")
        if c.method != "GET":
            parts.append(f"--method={c.method}" + (" --body-data=''" if c.method == "POST" else ""))
    parts += [f"'{c.url}'", f"| head -c {MAX_BODY} | awk 1"]
    return " ".join(parts)


STATUS_LINE = re.compile(r"^\s*HTTP/[\d.]+\s+(\d{3})\b", re.M)
CURL_ERROR = re.compile(r"curl: \((\d+)\)\s*(.*)")
# no HTTP response at all: couldn't connect (refused, timed out), timeout, empty reply, reset while receiving
CURL_NO_RESPONSE = {7, 28, 52, 56}
NOT_A_FIREWALL_VERDICT = re.compile(r"No route to host|Network is unreachable|Could not resolve", re.I)
WGET_NO_RESPONSE = re.compile(
    r"Connection refused|Connection reset|connection timed out|Read error|No data received|timed out", re.I
)
WGET_ERROR = re.compile(
    r"^.*(?:failed:|ERROR|unable to resolve|Unable to establish|cannot verify|unrecognized option|"
    r"invalid option|wget: ).*$",
    re.M | re.I,
)
WGET_LOG = re.compile(
    r"^(?:\s{2}\S|\d{4}-\d\d-\d\d \d\d:\d\d:\d\d |wget: |--\d|Connecting to |Resolving |HTTP request sent|"
    r"Length: |Saving to|\d+ redirections exceeded)"
)


def parse_curl(text: str) -> dict[str, Any]:
    """{status, body, error, no_response} from curl -sS -D - output (headers, blank line, body)."""
    err = CURL_ERROR.search(text)
    code = int(err.group(1)) if err else None
    out: dict[str, Any] = {"status": None, "body": "", "error": err.group(0).strip() if err else None}
    lines = [ln for ln in text.replace("\r", "").split("\n") if not ln.startswith("curl: (")]
    i = 0
    # one or more header blocks (100 Continue, proxies), each ended by a blank line
    while i < len(lines) and STATUS_LINE.match(lines[i]):
        out["status"] = int(STATUS_LINE.match(lines[i]).group(1))  # type: ignore[union-attr]
        i += 1
        while i < len(lines) and lines[i].strip():
            i += 1
        i += 1  # the blank line
    if out["status"] is not None:
        out["body"] = "\n".join(lines[i:])
        if code == 23:  # head -c closed the pipe on a long body: not a failure
            out["error"] = None
    out["no_response"] = (
        out["status"] is None
        and code is not None
        and (
            (code in CURL_NO_RESPONSE and not NOT_A_FIREWALL_VERDICT.search(err.group(2)))  # type: ignore[union-attr]
            or (code == 35 and bool(re.search(r"reset|timed out", err.group(2), re.I)))  # type: ignore[union-attr]
        )
    )
    return out


def parse_wget(text: str) -> dict[str, Any]:
    """{status, body, error, no_response} from wget -nv -S -O - output (headers indented, on stderr)."""
    text = text.replace("\r", "")
    statuses = STATUS_LINE.findall(text)
    status = int(statuses[-1]) if statuses else None
    body = "\n".join(ln for ln in text.split("\n") if not WGET_LOG.match(ln) and not WGET_ERROR.fullmatch(ln))
    err = WGET_ERROR.search(text)
    error = err.group(0).strip() if err else None
    if status is not None and error and ("ERROR" in error or "redirections" in error):
        error = None  # wget calls a 4xx/5xx or an unfollowed redirect an error; it is still a response
    no_response = (
        status is None and bool(WGET_NO_RESPONSE.search(text)) and not NOT_A_FIREWALL_VERDICT.search(text)
    )
    return {
        "status": status,
        "body": body.strip("\n") if status is not None else "",
        "error": error,
        "no_response": no_response,
    }


def http_verdict(c: HttpCheck, r: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    e = c.expect
    seen = {k: r[k] for k in ("status", "error") if r.get(k) is not None}
    if e.no_response:
        if r["no_response"]:
            return True, {**seen, "result": "no response"}
        why = (
            f"got HTTP {r['status']}" if r["status"] is not None else f"failed another way: {r.get('error')}"
        )
        return False, {**seen, "why": f"expected no response; {why}"}
    if r["status"] is None:
        return False, {**seen, "why": "no HTTP response"}
    wanted = e.statuses()
    if (r["status"] not in wanted) if wanted else not 200 <= r["status"] <= 299:
        return False, {**seen, "why": f"status {r['status']}, expected {wanted or '2xx'}"}
    if e.pattern and not re.search(e.pattern, r["body"], re.M):
        return False, {**seen, "why": f"pattern {e.pattern!r} not in the body"}
    if e.not_pattern and re.search(e.not_pattern, r["body"], re.M):
        return False, {**seen, "why": f"not_pattern {e.not_pattern!r} is in the body"}
    return True, seen


# --- dns --------------------------------------------------------------------------------------


def dns_command(tool: str, c: DnsCheck) -> str:
    ptr = c.record == "PTR"
    if tool == "dig":
        q = f"-x {c.name}" if ptr else f"{c.name} {c.record}"
        return f"dig +time=3 +tries=1 {'@' + c.server + ' ' if c.server else ''}{q}"
    if tool == "drill":
        q = f"-x {c.name}" if ptr else f"{c.name} {c.record}"
        return f"drill {'@' + c.server + ' ' if c.server else ''}{q}"
    if tool == "host":
        return f"host -W 3 -t {c.record} {c.name}{' ' + c.server if c.server else ''}"
    return f"nslookup -type={c.record} -timeout=3 {c.name}{' ' + c.server if c.server else ''}"


NO_REPLY = re.compile(
    r"connection timed out|no servers could be reached|error sending query|communications error.*timed out",
    re.I,
)
HEADER_RCODE = re.compile(r"->>HEADER<<-.*?(?:status|rcode): (\w+)")


def _section(text: str) -> list[str]:
    """rdata of each record in a dig/drill ANSWER SECTION ('name ttl class type rdata...')."""
    out, inside = [], False
    for line in text.replace("\r", "").split("\n"):
        if line.startswith(";; ANSWER SECTION"):
            inside = True
            continue
        if inside:
            if not line.strip() or line.startswith(";;"):
                break
            fields = line.split(None, 4)
            if len(fields) == 5:
                out.append(fields[4].strip())
    return out


HOST_ANSWER = re.compile(
    r"(?:has address|has IPv6 address|is an alias for|mail is handled by|name server|domain name pointer|"
    r"has SRV record|descriptive text) (.+)$"
)
NSLOOKUP_ANSWER = re.compile(
    r"^\s*(?:Address(?: \d+)?:|canonical name =|mail exchanger =|nameserver =|name =|text =|service =)"
    r"\s*(.+)$"
)


def parse_dns(tool: str, text: str) -> dict[str, Any]:
    """{rcode, answers, no_reply, error} from one tool's output."""
    text = text.replace("\r", "")
    out: dict[str, Any] = {"rcode": None, "answers": [], "no_reply": False, "error": None}
    header = HEADER_RCODE.search(text)
    if tool in ("dig", "drill") and header:
        out["rcode"], out["answers"] = header.group(1).upper(), _section(text)
    elif NO_REPLY.search(text):
        if re.search(r"connection refused", text, re.I):  # ICMP port unreachable: not a timeout
            out["error"] = "the server's port is unreachable (connection refused)"
        else:
            out["no_reply"] = True
    elif tool == "host" and not re.search(r"Usage:|invalid|not found: \d+\(timed out\)", text):
        m = re.search(r"not found: \d+\((\w+)\)", text)
        out["rcode"] = m.group(1).upper() if m else "NOERROR"
        out["answers"] = [a.group(1) for ln in text.split("\n") if (a := HOST_ANSWER.search(ln.strip()))]
    elif tool == "nslookup" and "Server:" in text:
        # the first block names the server; the answers follow it
        m = re.search(r"server can't find \S+?:? (\w+)", text)
        _, _, rest = text.strip().partition("\n\n")
        out["rcode"] = m.group(1).upper() if m else "NOERROR"
        out["answers"] = [a.group(1) for ln in rest.split("\n") if (a := NSLOOKUP_ANSWER.match(ln))]
    else:
        out["error"] = mask_secrets(text.strip())[-200:] or "no output"
    return out


def _norm(value: str) -> str:
    v = value.strip().strip('"').rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return v


def _candidates(rdata: list[str]) -> set[str]:
    """Each answer whole ('10 mail.example') and by its last word ('mail.example')."""
    out = set()
    for r in rdata:
        out.add(_norm(r))
        if r.split():
            out.add(_norm(r.split()[-1]))
    return out


def dns_verdict(c: DnsCheck, r: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    e = c.expect
    seen = {k: r[k] for k in ("rcode", "answers", "error") if r.get(k)}
    if e.no_response:
        if r["no_reply"]:
            return True, {"result": "no reply"}
        why = f"got {r['rcode']}" if r["rcode"] else f"failed another way: {r['error']}"
        return False, {**seen, "why": f"expected no reply; {why}"}
    if r["no_reply"]:
        return False, {"why": "no reply (timed out)"}
    if r["rcode"] is None:
        return False, {**seen, "why": "no DNS response parsed"}
    if r["rcode"] != e.rcode:
        return False, {**seen, "why": f"rcode {r['rcode']}, expected {e.rcode}"}
    have = _candidates(r["answers"])
    missing = [a for a in e.answers or [] if _norm(a) not in have]
    if missing:
        return False, {**seen, "why": f"missing answers {missing}"}
    present = [a for a in e.not_answers or [] if _norm(a) in have]
    if present:
        return False, {**seen, "why": f"unwanted answers {present}"}
    if e.rcode == "NOERROR" and not e.answers and not r["answers"]:
        return False, {**seen, "why": "NOERROR but no answers"}
    return True, seen


# --- running ----------------------------------------------------------------------------------


class AppProbe(BaseModel):
    """What run_app_probes needs from a verify probe: a name, a node, a timeout and the check."""

    name: str
    node: str
    timeout: float = Field(default=DEFAULT_TIMEOUT, gt=0, le=1800)
    http: HttpCheck | None = None
    dns: DnsCheck | None = None


def _tail(text: str) -> str:
    return mask_secrets(text.strip())[-300:]


def evaluate(p: AppProbe, tool: str, text: str) -> tuple[bool, dict[str, Any]]:
    if p.http:
        ok, detail = http_verdict(p.http, parse_curl(text) if tool == "curl" else parse_wget(text))
    else:
        assert p.dns
        ok, detail = dns_verdict(p.dns, parse_dns(tool, text))
    detail = {"tool": tool, **detail}
    if not ok:
        detail["output"] = _tail(text)
    return ok, detail


async def run_app_probes(
    app: CmlApp,
    lab_id: str,
    nodes: dict[str, dict[str, Any]],
    probes: list[AppProbe],
    *,
    interval: float = RETRY_INTERVAL,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> list[dict[str, Any]]:
    """Run http/dns probes from their nodes' consoles, retrying each until it passes or its timeout runs
    out. One result per probe: {check, kind, ok, detail} (detail has the tool, what was seen, why it failed
    and the output tail, plus the number of tries)."""
    started = time.monotonic()
    results: dict[str, dict[str, Any]] = {}

    def result(p: AppProbe, ok: bool, detail: Any) -> None:
        results[p.name] = {"check": p.name, "kind": "http" if p.http else "dns", "ok": ok, "detail": detail}

    labels = sorted({p.node for p in probes})
    ready = [lbl for lbl in labels if (nodes.get(lbl) or {}).get("state") == "BOOTED"]
    for p in probes:
        if p.node not in ready:
            result(p, False, f"node {p.node} not BOOTED; skipped")
    tools: dict[str, set[str]] = {}
    oses: dict[str, str | None] = {}
    if ready:

        def detect(node: dict[str, Any], cred: Credentials) -> list[Command]:
            oses[str(node.get("label"))] = cred.os
            return [TOOLS_COMMAND]

        for res in await console_batch(
            app, lab_id, [nodes[n] for n in ready], detect, timeout=30, purpose="cml_verify_recipe"
        ):
            outs = res.get("outputs") or []
            if res.get("error") or not outs or "error" in outs[0]:
                why = res.get("error") or (outs[0].get("error") if outs else "no output")
                for p in probes:
                    if p.node == res["node"]:
                        result(p, False, f"console failed: {why}")
                continue
            tools[str(res["node"])] = parse_tools(outs[0].get("output", ""))
    pending: list[tuple[AppProbe, str]] = []
    for p in probes:
        if p.name in results or p.node not in tools:
            continue
        os_name = (oses.get(p.node) or "").lower()
        if os_name and os_name != "linux":
            result(p, False, f"{p.node} is {os_name}; http and dns probes need a Linux node")
            continue
        wanted = HTTP_TOOLS if p.http else DNS_TOOLS
        tool = pick(tools[p.node], wanted)
        if not tool:
            result(p, False, f"{p.node} has none of {', '.join(wanted)}")
            continue
        pending.append((p, tool))
    tries: dict[str, int] = {}
    while pending:
        plan: dict[str, list[tuple[AppProbe, str]]] = {}
        for p, tool in pending:
            plan.setdefault(p.node, []).append((p, tool))

        def commands(
            node: dict[str, Any], cred: Credentials, plan: dict[str, list[tuple[AppProbe, str]]] = plan
        ) -> list[Command]:
            return [
                http_command(t, p.http) if p.http else dns_command(t, p.dns)  # type: ignore[arg-type]
                for p, t in plan[str(node.get("label"))]
            ]

        batch = await console_batch(
            app,
            lab_id,
            [nodes[n] for n in plan],
            commands,
            timeout=TRY_SECONDS + 20,
            purpose="cml_verify_recipe",
        )
        failed: list[tuple[AppProbe, str]] = []
        for res in batch:
            outs = res.get("outputs") or []
            for i, (p, tool) in enumerate(plan.get(str(res["node"]), [])):
                tries[p.name] = tries.get(p.name, 0) + 1
                o = outs[i] if i < len(outs) else {"error": res.get("error") or "no output"}
                if "error" in o:
                    ok, detail = False, {"tool": tool, "why": f"console: {o['error']}"}
                else:
                    ok, detail = evaluate(p, tool, o.get("output", ""))
                result(p, ok, {**detail, "tries": tries[p.name]})
                if not ok:
                    failed.append((p, tool))
        elapsed = time.monotonic() - started
        pending = [(p, t) for p, t in failed if elapsed + interval < p.timeout]
        if pending:
            await sleep(interval)
    return [results[p.name] for p in probes]
