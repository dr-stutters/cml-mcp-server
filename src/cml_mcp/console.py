"""Run CLI on lab nodes through the CML console server.

The controller runs an SSH "terminal server" (port 22, CML credentials). After login it shows a
`consoles>` prompt; `open /<lab id>/<node id>/0` attaches to a node's serial console - the same
path pyATS testbeds use. No IP reachability to the devices is needed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import asyncssh
import yaml
from stutters_mcp_core import AuthError, InvalidRequest, Unreachable, UpstreamTimeout

log = logging.getLogger(__name__)

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|[\x00\x07\x08]")
PROMPT = re.compile(r"(?:^|\n)([^\n]{0,80}?[#>$%])[ \t]?$")
MORE = re.compile(r" *(?:--\s?More\s?--|<--- More --->) *", re.IGNORECASE)
LOGIN = re.compile(r"(?:username|login)\s*:\s*$", re.IGNORECASE)
PASSWORD = re.compile(r"password\s*:\s*$", re.IGNORECASE)
PRESS_RETURN = re.compile(r"press return to get started", re.IGNORECASE)
CONFIG_DIALOG = re.compile(r"configuration dialog\?\s*\[yes/no\]:\s*$", re.IGNORECASE)


def clean(text: str) -> str:
    return re.sub(r"\r+\n?", "\n", ANSI.sub("", text))


# Read tier: commands that only display state. Anything else needs cml_configure_node (write tier).
# Commands are checked verb by verb; shell/CLI metacharacters are refused outright.
FORBIDDEN_CHARS = set(";&`$<>\\") | {chr(c) for c in range(32)} | {"\x7f"}
IOS_FILTERS = {
    "include",
    "inc",
    "i",
    "exclude",
    "exc",
    "e",
    "begin",
    "beg",
    "b",
    "section",
    "sec",
    "s",
    "count",
}
IP_OBJECTS = {"a", "addr", "address", "r", "ro", "route", "l", "link", "n", "neigh", "neighbor", "-br"}
IP_CHANGES = {
    "add",
    "del",
    "delete",
    "set",
    "flush",
    "change",
    "replace",
    "append",
    "prepend",
    "save",
    "restore",
    "exec",
    "netns",
}
SHOW_DENIED = ("tech",)


def read_only_problem(command: str) -> str | None:
    """None if `command` is allowed in the read tier, else why it isn't."""
    cmd = command.strip()
    if not cmd:
        return "empty command"
    if any(ch in FORBIDDEN_CHARS for ch in cmd):
        return "control characters and ; & ` $ < > \\ are not allowed"
    main, has_pipe, pipe = (part.strip() for part in cmd.partition("|"))
    words = main.split()
    verb = words[0].lower()
    args = [w.lower() for w in words[1:]]
    if verb in ("show", "sh"):
        if args and args[0].startswith(SHOW_DENIED):
            return "'show tech' is too large and secret-laden for this tool"
        # IOS allows one output filter; its regex may itself contain '|' (alternation)
        if has_pipe and (not pipe or pipe.split()[0].lower() not in IOS_FILTERS):
            return "after '|' only include/exclude/begin/section/count filters are allowed"
        return None
    if has_pipe:
        return "'|' is only allowed after show commands"
    if verb in ("ping", "traceroute", "trace"):
        return None if args else "give a target (interactive extended ping/traceroute is not supported)"
    if verb == "dir":
        return None
    if verb == "ip":
        rest = [a for a in args if a not in ("-4", "-6", "-s", "-d", "-br", "-brief", "-c", "-color")]
        if not rest or rest[0] not in IP_OBJECTS:
            return "only 'ip addr|route|link|neigh [show]' are read-only"
        if any(a in IP_CHANGES for a in rest[1:]):
            return "'ip ... add/del/set/flush' change state; use cml_configure_node"
        return None
    if verb == "ifconfig":
        return (
            None if len(args) <= 1 and not any(a.startswith("-") for a in args) else "only 'ifconfig [iface]'"
        )
    if verb in ("route", "arp", "netstat", "uname"):
        return (
            None
            if all(a.startswith("-") and a not in ("-s", "-d") for a in args)
            else f"only '{verb} -flags'"
        )
    if verb in ("uptime", "hostname") and not args:
        return None
    if cmd == "cat /etc/os-release":
        return None
    return "only show/ping/traceroute-style commands are allowed here; use cml_configure_node for changes"


SECRET_LINE = re.compile(
    r"(?im)^(.*\b(?:password|secret|key-string|key|community|psk|pre-shared-key|passphrase)\b\s+"
    r"(?:\d{1,2}\s+)?)(\S+)(.*)$"
)


def mask_secrets(text: str) -> str:
    """Mask the secret token in config lines like 'username x secret 9 $9$...', 'snmp-server community x'."""
    return SECRET_LINE.sub(lambda m: f"{m.group(1)}********{m.group(3)}", text)


@dataclass
class Credentials:
    username: str | None = None
    password: str | None = None
    enable: str | None = None


def testbed_credentials(testbed_yaml: str) -> dict[str, Credentials]:
    """{device label: credentials} from the lab's pyATS testbed."""
    data = yaml.safe_load(testbed_yaml) or {}
    out: dict[str, Credentials] = {}
    for name, dev in (data.get("devices") or {}).items():
        creds = (dev or {}).get("credentials") or {}
        default = creds.get("default") or {}
        enable = creds.get("enable") or {}
        out[str(name)] = Credentials(default.get("username"), default.get("password"), enable.get("password"))
    return out


class ConsoleSession:
    """One interactive console session on one node (after `open`)."""

    def __init__(self, proc: Any, creds: Credentials, timeout: float) -> None:
        self.proc = proc
        self.creds = creds
        self.timeout = timeout
        self.buffer = ""
        self.prompt = ""
        self.last_prompt = ""

    def redact(self, text: str) -> str:
        for secret in (self.creds.password, self.creds.enable):
            if secret:
                text = text.replace(secret, "********")
        return text

    def send(self, text: str) -> None:
        self.buffer = ""
        self.proc.stdin.write(text)

    async def read_until(self, done: Callable[[str], bool], timeout: float) -> str:  # noqa: ASYNC109
        """Read until done(cleaned buffer); answers --More-- pagers on the way."""
        deadline = time.monotonic() + timeout
        while True:
            text = clean(self.buffer)
            if done(text):
                return text
            if MORE.search(text[-60:]):
                self.buffer = MORE.sub("", self.buffer)
                self.proc.stdin.write(" ")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                tail = self.redact(text.strip()[-200:])
                raise UpstreamTimeout(f"No CLI prompt after {int(timeout)}s; last output: {tail!r}")
            try:
                chunk = await asyncio.wait_for(self.proc.stdout.read(4096), min(remaining, 1.0))
            except TimeoutError:
                continue
            if not chunk:
                raise Unreachable("The console connection closed unexpectedly")
            self.buffer += chunk

    async def wake(self) -> str:
        """Reach a CLI prompt: press RETURN, skip the setup dialog, log in, enable. Returns it."""
        logins = passwords = 0

        def ready(t: str) -> bool:
            return bool(
                PROMPT.search(t)
                or LOGIN.search(t)
                or PASSWORD.search(t)
                or PRESS_RETURN.search(t)
                or CONFIG_DIALOG.search(t)
            )

        self.send("\r")
        for _ in range(15):
            text = await self.read_until(ready, self.timeout)
            if CONFIG_DIALOG.search(text):
                self.send("no\r")
            elif PRESS_RETURN.search(text):
                self.send("\r")
            elif LOGIN.search(text):
                logins += 1
                if logins > 2 or not self.creds.username:
                    raise AuthError(
                        "The device asks for a login and no working credentials are known; set the "
                        "node's pyATS username/password in CML (they feed the lab's pyATS testbed)."
                    )
                self.send(self.creds.username + "\r")
            elif PASSWORD.search(text):
                passwords += 1
                if passwords > 2 or not self.creds.password:
                    raise AuthError(
                        "The device asks for a password and no working one is known; set the node's "
                        "pyATS credentials in CML."
                    )
                self.send(self.creds.password + "\r")
            else:
                m = PROMPT.search(text)
                prompt = m.group(1).strip() if m else ""
                if prompt.endswith(">"):
                    prompt = await self._enable(prompt)
                self.prompt = prompt
                return prompt
        raise UpstreamTimeout("Could not reach a CLI prompt on the console")

    async def _enable(self, prompt: str) -> str:
        self.send("enable\r")
        text = await self.read_until(lambda t: bool(PASSWORD.search(t) or PROMPT.search(t)), self.timeout)
        if PASSWORD.search(text):
            secret = self.creds.enable or self.creds.password
            if not secret:
                raise AuthError("'enable' asks for a password and none is known (pyATS enable password).")
            self.send(secret + "\r")
            text = await self.read_until(lambda t: bool(PROMPT.search(t)), self.timeout)
        m = PROMPT.search(text)
        return m.group(1).strip() if m else prompt

    def _prompt_re(self) -> re.Pattern[str]:
        # hostname plus anything mode-like: 'r1#', 'r1(config)#', 'r1(config-if)#', 'h1:~$'
        base = re.escape(re.split(r"[(:]", self.prompt[:-1], maxsplit=1)[0] or self.prompt[:-1])
        if not base:
            return re.compile(r"(?:^|\n)" + re.escape(self.prompt) + r"[ \t]?$")
        return re.compile(r"(?:^|\n)" + base + r"[^\n]{0,40}[#>$%][ \t]?$")

    async def drain(self, quiet: float = 0.3, limit: float = 3.0) -> None:
        """Discard late output (syslog lines, re-printed prompts) until the console is quiet."""
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            try:
                chunk = await asyncio.wait_for(self.proc.stdout.read(4096), quiet)
            except TimeoutError:
                break
            if not chunk:
                break
        self.buffer = ""

    async def run(self, command: str, timeout: float | None = None) -> str:  # noqa: ASYNC109
        """Send one command and return its output (without the echo and the trailing prompt)."""
        prompt = self._prompt_re()
        await self.drain()
        echo = command.strip()[:40]

        def after_echo(t: str) -> str | None:
            idx = t.find(echo) if echo else 0
            if idx < 0:
                return None
            nl = t.find("\n", idx)
            return None if nl < 0 else t[nl:]

        self.send(command + "\r")
        text = await self.read_until(
            lambda t: (rest := after_echo(t)) is not None and bool(prompt.search(rest)),
            timeout or self.timeout,
        )
        rest = after_echo(text) or ""
        lines = rest.split("\n")
        if lines and prompt.search("\n" + lines[-1]):
            self.last_prompt = lines[-1].strip()
            lines = lines[:-1]
        return "\n".join(line.rstrip() for line in lines).strip("\n")


class ConsoleServer:
    """Opens node consoles via SSH to the CML controller."""

    def __init__(
        self,
        url: str,
        username: str | None,
        password: str | None,
        *,
        port: int = 22,
        timeout: float = 30.0,
        known_hosts: Any = None,
    ) -> None:
        self.host = urlparse(url).hostname or ""
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.known_hosts = known_hosts
        self._locks: dict[str, asyncio.Lock] = {}
        self._warned = False

    def lock(self, node_id: str) -> asyncio.Lock:
        """One console session per node at a time."""
        return self._locks.setdefault(node_id, asyncio.Lock())

    def open(self, lab_id: str, node_id: str, creds: Credentials, line: int = 0) -> OpenConsole:
        if not self.username or not self.password:
            raise InvalidRequest(
                "Running commands needs CML_USERNAME/CML_PASSWORD: the console server logs in over SSH, "
                "a CML_TOKEN alone is not enough."
            )
        if self.known_hosts is None and not self._warned:
            self._warned = True
            log.warning(
                "The CML console server's SSH host key is not verified (CML_VERIFY_SSL=false and no "
                "CML_CONSOLE_KNOWN_HOSTS)"
            )
        return OpenConsole(self, f"/{lab_id}/{node_id}/{line}", creds)


class OpenConsole:
    def __init__(self, server: ConsoleServer, target: str, creds: Credentials) -> None:
        self.server = server
        self.target = target
        self.creds = creds
        self.conn: Any = None
        self.proc: Any = None

    async def __aenter__(self) -> ConsoleSession:
        s = self.server
        try:
            self.conn = await asyncio.wait_for(
                asyncssh.connect(
                    s.host,
                    port=s.port,
                    username=s.username,
                    password=s.password,
                    known_hosts=s.known_hosts,
                    client_keys=None,
                    agent_path=None,
                ),
                s.timeout,
            )
        except asyncssh.PermissionDenied as e:
            raise AuthError(f"The CML console server rejected the SSH login: {e}") from e
        except asyncssh.HostKeyNotVerifiable as e:
            raise Unreachable(
                f"The console server's SSH host key is not trusted ({e}). Add it to CML_CONSOLE_KNOWN_HOSTS "
                "(e.g. ssh-keyscan) or ~/.ssh/known_hosts."
            ) from e
        except (OSError, asyncssh.Error, TimeoutError) as e:
            raise Unreachable(f"Could not reach the CML console server at {s.host}:{s.port}: {e}") from e
        try:
            self.proc = await asyncio.wait_for(
                self.conn.create_process(term_type="vt100", term_size=(250, 60)), s.timeout
            )
            session = ConsoleSession(self.proc, self.creds, s.timeout)
            await session.read_until(lambda t: "consoles>" in t, s.timeout)
            session.send(f"open {self.target}\n")
            text = await session.read_until(
                lambda t: "Escape character" in t or bool(re.search(r"not found|error|invalid", t, re.I)),
                s.timeout,
            )
            if "Escape character" not in text:
                detail = session.redact(text.strip()[-200:])
                raise InvalidRequest(f"The console server could not open {self.target}: {detail}")
            await session.wake()
            return session
        except BaseException:
            await self._close()
            raise

    async def __aexit__(self, *exc: object) -> None:
        if self.proc is not None:
            with contextlib.suppress(Exception):
                self.proc.stdin.write("\x1d")  # escape back to the console server before hanging up
                await asyncio.sleep(0.2)
        await self._close()

    async def _close(self) -> None:
        if self.proc is not None:
            self.proc.close()
        if self.conn is not None:
            self.conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.conn.wait_closed(), 5)
