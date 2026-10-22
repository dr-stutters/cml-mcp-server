"""http and dns probes (CML Cookbook check types): commands, parsers of real tool output, verdicts, and the
retrying runner through cml_verify_recipe."""

from typing import Any

import pytest
import respx
from pydantic import ValidationError

from cml_mcp._core.testing import call_tool
from cml_mcp.appchecks import (
    DnsCheck,
    HttpCheck,
    dns_command,
    dns_verdict,
    http_command,
    http_verdict,
    parse_curl,
    parse_dns,
    parse_tools,
    parse_wget,
)
from cml_mcp.console import FORBIDDEN_CHARS, ConsoleServer, ConsoleSession, Credentials
from cml_mcp.server import create_server
from cml_mcp.verify import contract_of

from .conftest import LAB, make_settings
from .test_console import FakeDevice


def http(**kw: Any) -> HttpCheck:
    return HttpCheck(url=kw.pop("url", "http://10.20.0.10/"), **kw)


def dns(**kw: Any) -> DnsCheck:
    return DnsCheck(name=kw.pop("name", "app.lab.example"), **kw)


# --- sample tool output -----------------------------------------------------------------------

CURL_200 = (
    "HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n\n<html><body>\n<h1>Welcome to the app</h1>\n"
    "</body></html>\n"
)
CURL_302 = "HTTP/1.1 302 Found\nLocation: http://block.lab.example/\nContent-Length: 0\n\n\n"
CURL_403_BLOCK = "HTTP/1.1 403 Forbidden\nContent-Type: text/html\n\n<html>Blocked by policy</html>\n"
CURL_100_CONTINUE = "HTTP/1.1 100 Continue\n\nHTTP/1.1 201 Created\nContent-Length: 2\n\nok\n"
CURL_REFUSED = "curl: (7) Failed to connect to 10.20.0.10 port 80 after 2 ms: Connection refused\n"
CURL_COULDNT = "curl: (7) Failed to connect to 10.20.0.10 port 80 after 3 ms: Couldn't connect to server\n"
CURL_TIMEOUT = "curl: (28) Connection timed out after 10001 milliseconds\n"
CURL_RESET = "curl: (56) Recv failure: Connection reset by peer\n"
CURL_TLS_RESET = "curl: (35) OpenSSL SSL_connect: Connection reset by peer in connection to 10.20.0.10:443\n"
CURL_EMPTY = "curl: (52) Empty reply from server\n"
CURL_NO_ROUTE = "curl: (7) Failed to connect to 10.20.0.10 port 80 after 1 ms: No route to host\n"
CURL_DNS = "curl: (6) Could not resolve host: app.lab.example\n"
CURL_CERT = (
    "curl: (60) SSL certificate problem: self-signed certificate\nMore details here: https://curl.se/docs/"
    "sslcerts.html\n"
)
CURL_TRUNCATED = "HTTP/1.1 200 OK\n\n" + "x" * 100 + "\ncurl: (23) Failure writing output to destination\n"

WGET_200 = (
    "  HTTP/1.1 200 OK\n  Server: nginx\n  Content-Type: text/html\n"
    "<html><h1>Welcome to the app</h1></html>\n"
    '2026-10-22 08:00:00 URL:http://10.20.0.10/ [44/44] -> "-" [1]\n'
)
WGET_301 = "  HTTP/1.1 301 Moved Permanently\n  Location: https://10.20.0.10/\n0 redirections exceeded.\n"
WGET_REFUSED = "failed: Connection refused.\n"
WGET_TIMEOUT = "failed: Connection timed out.\n"
WGET_RESET = "Read error (Connection reset by peer) in headers.\n"

DIG_A = """
; <<>> DiG 9.18.18-0ubuntu0.22.04.2-Ubuntu <<>> +time=3 +tries=1 @10.20.0.53 app.lab.example A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4242
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;app.lab.example.               IN      A

;; ANSWER SECTION:
app.lab.example.        300     IN      A       10.20.0.10

;; Query time: 1 msec
;; SERVER: 10.20.0.53#53(10.20.0.53) (UDP)
"""
DIG_SINKHOLE = DIG_A.replace("app.lab.example", "malware.lab.example").replace("10.20.0.10", "10.99.99.99")
DIG_CNAME = DIG_A.replace(
    "app.lab.example.        300     IN      A       10.20.0.10",
    "www.lab.example.        300     IN      CNAME   app.lab.example.\n"
    "app.lab.example.        300     IN      A       10.20.0.10",
)
DIG_MX = DIG_A.replace("IN      A       10.20.0.10", "IN      MX      10 mail.lab.example.")
DIG_NXDOMAIN = """
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 5151
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; AUTHORITY SECTION:
lab.example.            300     IN      SOA     ns.lab.example. admin.lab.example. 1 3600 600 86400 300
"""
DIG_NODATA = DIG_NXDOMAIN.replace("NXDOMAIN", "NOERROR")
DIG_TIMEOUT = ";; communications error to 10.20.0.53#53: timed out\n;; no servers could be reached\n"
DIG_OLD_TIMEOUT = (
    "\n; <<>> DiG 9.16.1 <<>> app.lab.example\n;; connection timed out; no servers could be reached\n"
)
DIG_BAD_SERVER = "dig: couldn't get address for 'ns.nowhere': not found\n"

DRILL_A = """;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 31337
;; flags: qr aa rd ra ; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; QUESTION SECTION:
;; app.lab.example.\tIN\tA

;; ANSWER SECTION:
app.lab.example.\t300\tIN\tA\t10.20.0.10

;; AUTHORITY SECTION:
"""
DRILL_TIMEOUT = "Error: error sending query: Could not send or receive, because of network error\n"

HOST_A = "app.lab.example has address 10.20.0.10\n"
HOST_A_WITH_SERVER = (
    "Using domain server:\nName: 10.20.0.53\nAddress: 10.20.0.53#53\nAliases: \n\n"
    "app.lab.example has address 10.20.0.10\n"
)
HOST_NX = "Host nope.lab.example not found: 3(NXDOMAIN)\n"
HOST_SERVFAIL = "Host app.lab.example not found: 2(SERVFAIL)\n"
HOST_TIMEOUT = ";; connection timed out; no servers could be reached\n"

NSLOOKUP_A = (
    "Server:\t\t10.20.0.53\nAddress:\t10.20.0.53#53\n\nName:\tapp.lab.example\nAddress: 10.20.0.10\n\n"
)
NSLOOKUP_BUSYBOX = (
    "Server:\t\t10.20.0.53\nAddress:\t10.20.0.53:53\n\nName:\tapp.lab.example\nAddress 1: 10.20.0.10\n"
)
NSLOOKUP_NX = (
    "Server:\t\t10.20.0.53\nAddress:\t10.20.0.53#53\n\n** server can't find nope.lab.example: NXDOMAIN\n"
)
DNS_PORT_CLOSED = (
    ";; communications error to 10.20.0.53#53: connection refused\n;; no servers could be reached\n"
)
NSLOOKUP_TIMEOUT = ";; connection timed out; no servers could be reached\n"


# --- commands ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "check", "parts"),
    [
        ("curl", http(), ["curl -sS -g", "-D -", "'http://10.20.0.10/'", "| head -c 65536 | awk 1"]),
        ("curl", http(url="https://x.lab/", insecure=True, method="HEAD"), ["-k", "-I"]),
        ("curl", http(method="POST"), ["-X POST --data ''"]),
        ("wget", http(insecure=True), ["--max-redirect=0", "--no-check-certificate", "--content-on-error"]),
    ],
)
def test_http_command(tool: str, check: HttpCheck, parts: list[str]) -> None:
    cmd = http_command(tool, check)
    assert all(p in cmd for p in parts), cmd
    assert not any(ch in FORBIDDEN_CHARS for ch in cmd)
    assert "-L" not in cmd.split()  # redirects are never followed


@pytest.mark.parametrize(
    ("tool", "check", "expected"),
    [
        ("dig", dns(server="10.20.0.53"), "dig +time=3 +tries=1 @10.20.0.53 app.lab.example A"),
        ("dig", dns(name="10.20.0.10", record="PTR"), "dig +time=3 +tries=1 -x 10.20.0.10"),
        ("drill", dns(record="MX"), "drill app.lab.example MX"),
        ("host", dns(server="10.20.0.53"), "host -W 3 -t A app.lab.example 10.20.0.53"),
        ("nslookup", dns(record="AAAA"), "nslookup -type=AAAA -timeout=3 app.lab.example"),
    ],
)
def test_dns_command(tool: str, check: DnsCheck, expected: str) -> None:
    assert dns_command(tool, check) == expected


@pytest.mark.parametrize(
    "bad",
    [
        {"url": "ftp://x/"},
        {"url": "http://x/'; reboot '"},
        {"url": "http://x/$(id)"},
        {"url": "http://x/ y"},
        {"url": "http://x/", "expect": {"no_response": True, "status": 200}},
        {"url": "http://x/", "expect": {"status": 999}},
        {"url": "http://x/", "expect": {"pattern": "("}},
        {"url": "http://x/", "method": "DELETE"},
    ],
)
def test_http_check_validation(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HttpCheck(**bad)


@pytest.mark.parametrize(
    "bad",
    [
        {"name": "x; rm -rf /"},
        {"name": "x", "server": "1.1.1.1 && id"},
        {"name": "x", "record": "ANY"},
        {"name": "x", "expect": {"no_response": True, "rcode": "NOERROR"}},
        {"name": "x", "expect": {"rcode": "NXDOMAIN", "answers": ["1.2.3.4"]}},
    ],
)
def test_dns_check_validation(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        DnsCheck(**bad)


def test_tools_detected_from_command_v() -> None:
    out = "/usr/bin/curl\n/usr/bin/dig\n/usr/bin/host\n"
    assert parse_tools(out) == {"curl", "dig", "host"}
    assert parse_tools("") == set()


# --- http verdicts ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("check", "output", "ok"),
    [
        (http(), CURL_200, True),  # default: any 2xx
        (http(expect={"status": 200, "pattern": "Welcome"}), CURL_200, True),
        (http(expect={"pattern": "^<h1>Welcome"}), CURL_200, True),  # multiline
        (http(expect={"not_pattern": "Blocked"}), CURL_200, True),
        (http(expect={"pattern": "Blocked"}), CURL_200, False),
        (http(expect={"not_pattern": "Welcome"}), CURL_200, False),
        (http(expect={"pattern": "Server: nginx"}), CURL_200, False),  # headers aren't the body
        (http(expect={"status": 404}), CURL_200, False),
        (http(), CURL_302, False),  # not followed: a 3xx isn't 2xx
        (http(expect={"status": [301, 302]}), CURL_302, True),
        (http(expect={"status": 403, "pattern": "Blocked"}), CURL_403_BLOCK, True),
        (http(), CURL_403_BLOCK, False),
        (http(expect={"no_response": True}), CURL_403_BLOCK, False),  # a block page is a response
        (http(expect={"status": 201, "pattern": "^ok$"}), CURL_100_CONTINUE, True),
        (http(expect={"pattern": "x{100}"}), CURL_TRUNCATED, True),
        (http(), CURL_REFUSED, False),
        (http(insecure=False), CURL_CERT, False),
    ],
)
def test_http_verdict_curl(check: HttpCheck, output: str, ok: bool) -> None:
    got, detail = http_verdict(check, parse_curl(output))
    assert got is ok, detail
    if not ok:
        assert detail["why"]


@pytest.mark.parametrize(
    ("output", "ok"),
    [
        (CURL_REFUSED, True),
        (CURL_COULDNT, True),
        (CURL_TIMEOUT, True),
        (CURL_RESET, True),
        (CURL_TLS_RESET, True),
        (CURL_EMPTY, True),
        (CURL_200, False),
        (CURL_NO_ROUTE, False),
        (CURL_DNS, False),
        (CURL_CERT, False),
    ],
)
def test_http_no_response_curl(output: str, ok: bool) -> None:
    got, detail = http_verdict(http(expect={"no_response": True}), parse_curl(output))
    assert got is ok, detail


@pytest.mark.parametrize(
    ("check", "output", "ok"),
    [
        (http(expect={"status": 200, "pattern": "Welcome"}), WGET_200, True),
        (http(expect={"pattern": "Server: nginx"}), WGET_200, False),
        (http(), WGET_301, False),
        (http(expect={"status": 301}), WGET_301, True),
        (http(), WGET_REFUSED, False),
        (http(expect={"no_response": True}), WGET_REFUSED, True),
        (http(expect={"no_response": True}), WGET_TIMEOUT, True),
        (http(expect={"no_response": True}), WGET_RESET, True),
        (http(expect={"no_response": True}), WGET_200, False),
    ],
)
def test_http_verdict_wget(check: HttpCheck, output: str, ok: bool) -> None:
    got, detail = http_verdict(check, parse_wget(output))
    assert got is ok, detail


# --- dns verdicts -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "check", "output", "ok"),
    [
        ("dig", dns(), DIG_A, True),  # NOERROR and at least one answer
        ("dig", dns(expect={"answers": ["10.20.0.10"]}), DIG_A, True),
        ("dig", dns(expect={"answers": ["10.20.0.11"]}), DIG_A, False),
        ("dig", dns(expect={"not_answers": ["10.20.0.10"]}), DIG_A, False),
        ("dig", dns(expect={"answers": ["10.99.99.99"], "not_answers": ["10.20.0.66"]}), DIG_SINKHOLE, True),
        ("dig", dns(expect={"answers": ["10.99.99.99"]}), DIG_A, False),
        ("dig", dns(expect={"answers": ["app.lab.example", "10.20.0.10"]}), DIG_CNAME, True),
        ("dig", dns(expect={"answers": ["app.lab.example."]}), DIG_CNAME, True),  # trailing dot ignored
        ("dig", dns(record="MX", expect={"answers": ["mail.lab.example"]}), DIG_MX, True),
        ("dig", dns(record="MX", expect={"answers": ["10 mail.lab.example"]}), DIG_MX, True),
        ("dig", dns(expect={"rcode": "NXDOMAIN"}), DIG_NXDOMAIN, True),
        ("dig", dns(), DIG_NXDOMAIN, False),
        ("dig", dns(), DIG_NODATA, False),  # NOERROR but no answers
        ("dig", dns(), DIG_TIMEOUT, False),
        ("dig", dns(), DIG_BAD_SERVER, False),
        ("drill", dns(expect={"answers": ["10.20.0.10"]}), DRILL_A, True),
        ("host", dns(expect={"answers": ["10.20.0.10"]}), HOST_A, True),
        ("host", dns(expect={"answers": ["10.20.0.10"]}), HOST_A_WITH_SERVER, True),
        (
            "host",
            dns(expect={"answers": ["10.20.0.53"]}),
            HOST_A_WITH_SERVER,
            False,
        ),  # the server isn't an answer
        ("host", dns(expect={"rcode": "NXDOMAIN"}), HOST_NX, True),
        ("host", dns(expect={"rcode": "SERVFAIL"}), HOST_SERVFAIL, True),
        ("host", dns(), HOST_NX, False),
        ("nslookup", dns(expect={"answers": ["10.20.0.10"]}), NSLOOKUP_A, True),
        ("nslookup", dns(expect={"answers": ["10.20.0.53"]}), NSLOOKUP_A, False),
        ("nslookup", dns(expect={"answers": ["10.20.0.10"]}), NSLOOKUP_BUSYBOX, True),
        ("nslookup", dns(expect={"rcode": "NXDOMAIN"}), NSLOOKUP_NX, True),
    ],
)
def test_dns_verdict(tool: str, check: DnsCheck, output: str, ok: bool) -> None:
    got, detail = dns_verdict(check, parse_dns(tool, output))
    assert got is ok, detail


@pytest.mark.parametrize(
    ("tool", "output", "ok"),
    [
        ("dig", DIG_TIMEOUT, True),
        ("dig", DIG_OLD_TIMEOUT, True),
        ("drill", DRILL_TIMEOUT, True),
        ("host", HOST_TIMEOUT, True),
        ("nslookup", NSLOOKUP_TIMEOUT, True),
        ("dig", DIG_A, False),
        ("dig", DIG_NXDOMAIN, False),  # an answer, even "not found", is a reply
        ("dig", DIG_BAD_SERVER, False),
        ("host", DNS_PORT_CLOSED, False),  # ICMP port unreachable is not a timeout
    ],
)
def test_dns_no_response(tool: str, output: str, ok: bool) -> None:
    got, detail = dns_verdict(dns(expect={"no_response": True}), parse_dns(tool, output))
    assert got is ok, detail


def test_ipv6_answers_compare_normalised() -> None:
    out = DIG_A.replace("IN      A       10.20.0.10", "IN      AAAA    2001:db8:0:0::10")
    assert dns_verdict(dns(record="AAAA", expect={"answers": ["2001:DB8::10"]}), parse_dns("dig", out))[0]


# --- through cml_verify_recipe ----------------------------------------------------------------


def _linux_console(monkeypatch: pytest.MonkeyPatch, replies: dict[str, list[str]], seen: list[str]) -> None:
    """A Linux shell answering by command prefix; each prefix's replies are used in turn, the last repeats."""

    def reply(text: str) -> str:
        cmd = text.rstrip("\r")
        if not cmd:
            return "\r\nr1:~$ "
        seen.append(cmd)
        if cmd.startswith("command -v"):
            out = "/usr/bin/curl\n/usr/bin/dig"
        else:
            key = next(k for k in replies if cmd.startswith(k))
            out = replies[key].pop(0) if len(replies[key]) > 1 else replies[key][0]
        return cmd + "\r\n" + out.replace("\n", "\r\n") + "\r\nr1:~$ "

    class Opened:
        def __init__(self, creds: Credentials) -> None:
            self.creds = creds

        async def __aenter__(self) -> ConsoleSession:
            s = ConsoleSession(FakeDevice(reply), self.creds, timeout=2)
            await s.wake()
            return s

        async def __aexit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(ConsoleServer, "open", lambda self, lab, node, creds, line=0: Opened(creds))


def _app_recipe(monkeypatch: pytest.MonkeyPatch, probes: list[dict[str, Any]]) -> None:
    import cml_mcp.recipes as recipes

    recipe: dict[str, Any] = {
        "name": "fake-app",
        "build": {"title": LAB["lab_title"], "nodes": [{"label": "r1", "definition": "ubuntu"}]},
        "verify": {"nodes": [], "targets": [], "probes": probes},
    }
    real = recipes._load_all()
    monkeypatch.setattr(recipes, "_load_all", lambda: {**real, "fake-app": recipe})


PROBES = [
    {
        "name": "app-page",
        "node": "r1",
        "http": {"url": "http://10.20.0.10/", "expect": {"pattern": "Welcome"}},
    },
    {
        "name": "eicar-blocked",
        "node": "r1",
        "timeout": 1,
        "http": {"url": "http://10.20.0.10/eicar.com", "expect": {"no_response": True}},
    },
    {
        "name": "app-resolves",
        "node": "r1",
        "dns": {"name": "app.lab.example", "expect": {"answers": ["10.20.0.10"]}},
    },
    {
        "name": "sinkholed",
        "node": "r1",
        "timeout": 1,
        "dns": {"name": "malware.lab.example", "expect": {"answers": ["10.99.99.99"]}},
    },
]


def test_probe_contract_accepts_http_and_dns() -> None:
    c = contract_of({"verify": {"probes": PROBES}})
    assert [p.app_probe().timeout for p in c.probes] == [180, 1, 180, 1]
    with pytest.raises(ValueError, match="needs a"):
        contract_of({"verify": {"probes": [{"name": "x", "http": {"url": "http://x/"}}]}})


async def test_verify_runs_http_and_dns(lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    _app_recipe(monkeypatch, PROBES)
    seen: list[str] = []
    _linux_console(
        monkeypatch,
        {
            "curl -sS -g --max-time 10 -D - 'http://10.20.0.10/'": [CURL_200],
            "curl -sS -g --max-time 10 -D - 'http://10.20.0.10/eicar.com'": [CURL_TIMEOUT],
            "dig +time=3 +tries=1 app.lab.example": [DIG_A],
            "dig +time=3 +tries=1 malware.lab.example": [DIG_SINKHOLE],
        },
        seen,
    )
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake-app"})
    app = {c["check"]: c for c in data["checks"] if c["kind"] in ("http", "dns")}
    assert set(app) == {"app-page", "eicar-blocked", "app-resolves", "sinkholed"}
    assert all(c["ok"] for c in app.values()), app
    assert app["app-page"]["detail"]["status"] == 200 and app["app-page"]["detail"]["tool"] == "curl"


async def test_verify_reports_failures_with_output(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    _app_recipe(monkeypatch, [p for p in PROBES if p.get("timeout") == 1])
    seen: list[str] = []
    _linux_console(
        monkeypatch,
        {"curl": [CURL_403_BLOCK], "dig": [DIG_A.replace("app.lab", "malware.lab")]},
        seen,
    )
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake-app"})
    app = {c["check"]: c for c in data["checks"] if c["kind"] in ("http", "dns")}
    assert data["passed"] is False
    assert not app["eicar-blocked"]["ok"] and "HTTP 403" in app["eicar-blocked"]["detail"]["why"]
    assert "Blocked by policy" in app["eicar-blocked"]["detail"]["output"]
    assert not app["sinkholed"]["ok"] and "10.99.99.99" in app["sinkholed"]["detail"]["why"]
    assert "10.20.0.10" in app["sinkholed"]["detail"]["output"]


async def test_failing_probe_is_retried_until_it_passes(
    lab_api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cml_mcp.appchecks as appchecks

    async def no_wait(_: float) -> None:
        return None

    monkeypatch.setattr(appchecks.asyncio, "sleep", no_wait)
    _app_recipe(monkeypatch, [PROBES[0]])
    seen: list[str] = []
    _linux_console(monkeypatch, {"curl": [CURL_REFUSED, CURL_REFUSED, CURL_200]}, seen)
    data = await call_tool(create_server(make_settings()), "cml_verify_recipe", {"recipe": "fake-app"})
    (page,) = [c for c in data["checks"] if c["kind"] == "http"]
    assert page["ok"] and page["detail"]["tries"] == 3, page
    assert sum(c.startswith("curl") for c in seen) == 3
