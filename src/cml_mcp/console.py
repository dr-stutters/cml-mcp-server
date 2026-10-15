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
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import asyncssh
import yaml
from stutters_mcp_core import AuthError, InvalidRequest, Unreachable, UpstreamError, UpstreamTimeout

log = logging.getLogger(__name__)

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|[\x00\x07\x08]")
PROMPT = re.compile(r"(?:^|\n)([^\n]{0,80}?[#>$%])[ \t]?$")
MORE = re.compile(r" *(?:--\s?More\s?--|<--- More --->) *", re.IGNORECASE)
LOGIN = re.compile(r"(?:username|login)\s*:\s*$", re.IGNORECASE)
PASSWORD = re.compile(r"password\s*:\s*$", re.IGNORECASE)
NEW_PASSWORD = re.compile(r"(?:enter|confirm) new password\s*:\s*$", re.IGNORECASE)
PRESS_RETURN = re.compile(r"press return to get started", re.IGNORECASE)
# A login prompt on its own final line ('Username:', 'h1 login:'): a session that was logged out.
# FTD (clish) answers a bad command with 'Syntax error: ...' and then re-prints the prompt with the
# rejected command already typed in, waiting for an edit: there's no bare prompt to wait for.
# Only checked on FTD sessions, and only when the last line is the prompt plus the command just sent.
REFILLED = re.compile(r"(?m)^Syntax error[^\n]*\n(?P<line>[^\n]*)$")
REFILL_OS = ("fxos", "ftd")
LOGIN_LINE = re.compile(r"(?:^|\n)[ \t]*(?:[\w.-]+[ \t]+)?(?:username|login)[ \t]*:[ \t]*$", re.IGNORECASE)
PRESS_RETURN_LINE = re.compile(r"press return to get started!?[ \t]*\n?[ \t]*$", re.IGNORECASE)
# How long the device must stay quiet after a login-looking tail before it counts as a lost session.
LOGOUT_QUIET = 2.0
CONFIG_DIALOG = re.compile(r"configuration dialog\?\s*\[yes/no\]:\s*$", re.IGNORECASE)
# NX-OS first boot without a day-0 config: skip Power On Auto Provisioning.
POAP = re.compile(r"Abort (?:Power On )?Auto Provisioning.*:\s*$", re.IGNORECASE | re.DOTALL)
# Questions a command asks before it acts ('[confirm]', '[yes/no]:', '(y/n)', 'Do you want to continue?').
QUESTION = re.compile(
    r"(?:\[confirm\]|\[(?:yes/no|y/n)\]\s*[:?]?|\((?:yes/no|y/n)\)\s*[:?]?|continue\s*\?\s*:?"
    r"|\[[^\]\n]{1,60}\]\?)[ \t]*$",
    re.IGNORECASE,
)


class ConsoleBusy(InvalidRequest):
    """Another call in this process holds the node's console."""


class SessionLost(UpstreamError):
    """The device dropped back to a login/RETURN prompt mid-command (reboot, wipe, idle logout)."""


def auto_answer(question: str) -> str:
    """The affirmative/default answer to a CLI question: 'yes', 'y' or just RETURN."""
    q = question.lower()
    if "y/n" in q and "yes/no" not in q:
        return "y"
    if "yes/no" in q or "continue" in q:
        return "yes"
    return ""  # '[confirm]', 'Destination filename [startup-config]?': RETURN takes the default


# Firepower Threat Defense (CLISH): the '>' prompt is the top level; there is no 'enable'.
NO_ENABLE_OS = frozenset({"fxos", "ftd"})


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


# Secret masking for device CLI output and configs. Line by line: nothing may span a newline.
_SP = r"[ \t]+"
_TYPE = (
    rf"(?:\d{{1,2}}{_SP})?"  # an encryption type digit before the secret ('secret 9 $9$...', 'key 7 0822')
)
_M = "********"
# Specific forms first (the first one that matches a line wins); each masks group 'secret'.
SECRET_FORMS = [
    # ip ospf message-digest-key 1 md5 7 X / ntp authentication-key 1 md5 X 7
    re.compile(
        rf"\b(?:message-digest-key|authentication-key){_SP}\d+{_SP}(?:md5|sha\S*){_SP}{_TYPE}(?P<secret>\S+)",
        re.I,
    ),
    # wpa-psk ascii 7 X
    re.compile(rf"\bwpa-psk{_SP}(?:ascii|hex){_SP}{_TYPE}(?P<secret>\S+)", re.I),
    # IKEv2 keyring 'pre-shared-key [local|remote] [hex] [0|6|7] X'; ASA 'ikev1 pre-shared-key X'
    re.compile(
        rf"\bpre-shared-key{_SP}(?:(?:local|remote){_SP})?(?:hex{_SP})?{_TYPE}(?!address\b|hostname\b)(?P<secret>\S+)",
        re.I,
    ),
    # snmp-server host H [informs|traps] [version 1|2c|3 [auth|noauth|priv]] COMMUNITY
    re.compile(
        rf"^\s*snmp-server{_SP}host{_SP}\S+(?:{_SP}(?:informs|traps))?(?:{_SP}version{_SP}(?:1|2c|3(?:{_SP}(?:auth|noauth|priv))?))?"
        rf"{_SP}(?!community\b)(?P<secret>\S+)",
        re.I,
    ),
]
# snmp-server user U G v3 auth sha X priv aes 128 Y: both secrets
SNMP_USER = re.compile(rf"^\s*snmp-server{_SP}user\b", re.I)
SNMP_USER_SECRETS = re.compile(
    rf"\b(?P<kw>auth{_SP}(?:md5|sha\S*)|priv{_SP}(?:des\S*|3des|aes(?:{_SP}\d{{3}})?)){_SP}{_TYPE}(?P<secret>\S+)",
    re.I,
)
# Generic 'keyword [type] secret'. 'key chain', 'crypto key generate', 'pre-shared-key address' etc.
# are not secrets.
GENERIC_SECRET = re.compile(
    rf"\b(?:password|secret|key-string|key|community|psk|pre-shared-key|passphrase|server-key){_SP}{_TYPE}"
    r"(?!(?:chain|generate|config-key|zeroize|import|export|storage|label|pubkey|address|hostname|"
    r"encryption|exchange|pair|rotation|hash)\b)(?P<secret>[^\s*]\S*)",
    re.I,
)


def _mask_group(m: re.Match[str]) -> str:
    whole, start = m.group(0), m.start("secret") - m.start(0)
    return whole[:start] + _M + whole[m.end("secret") - m.start(0) :]


def mask_line(line: str) -> str:
    if SNMP_USER.match(line):
        return SNMP_USER_SECRETS.sub(_mask_group, line)
    for form in SECRET_FORMS:
        masked, n = form.subn(_mask_group, line, count=1)
        if n:
            return masked
    return GENERIC_SECRET.sub(_mask_group, line)


def mask_secrets(text: str) -> str:
    """Mask the secret token in config/CLI lines: 'username x secret 9 $9$...', 'snmp-server
    community x', 'key 7 ...', OSPF/NTP keys, IKE pre-shared keys, SNMPv3 users, trap communities.
    Works line by line, so a keyword at a line end never swallows the next line."""
    return "\n".join(mask_line(line) for line in text.split("\n"))


@dataclass
class Credentials:
    username: str | None = None
    password: str | None = None
    enable: str | None = None
    os: str | None = None  # pyATS os from the testbed: ios, iosxe, nxos, fxos (FTD), asa, linux...


def testbed_credentials(testbed_yaml: str) -> dict[str, Credentials]:
    """{device label: credentials} from the lab's pyATS testbed."""
    data = yaml.safe_load(testbed_yaml) or {}
    out: dict[str, Credentials] = {}
    for name, dev in (data.get("devices") or {}).items():
        creds = (dev or {}).get("credentials") or {}
        default = creds.get("default") or {}
        enable = creds.get("enable") or {}
        os_name = (dev or {}).get("os")
        out[str(name)] = Credentials(
            default.get("username"),
            default.get("password"),
            enable.get("password"),
            str(os_name) if os_name else None,
        )
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
        # True while the console sits at a CLI prompt after a command that completed normally
        self.at_prompt = False

    def redact(self, text: str) -> str:
        for secret in (self.creds.password, self.creds.enable):
            if secret:
                text = text.replace(secret, "********")
        return text

    def safe(self, text: str) -> str:
        """Text for error messages: known passwords and config secrets masked."""
        return mask_secrets(self.redact(text))

    async def _more_output(self, quiet: float) -> bool:
        """True (and the buffer extended) if the device sends more within `quiet` seconds."""
        try:
            chunk = await asyncio.wait_for(self.proc.stdout.read(4096), quiet)
        except TimeoutError:
            return False
        if not chunk:
            raise Unreachable("The console connection closed unexpectedly")
        self.buffer += chunk
        return True

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
                or POAP.search(t[-300:])
            )

        # A bare RETURN would confirm a question left pending on the console; run() therefore
        # never leaves one behind (unanswered questions and timeouts are cancelled with Ctrl-C).
        # Sending Ctrl-C here instead breaks IOS's 'Username:' prompt on a fresh console.
        self.send("\r")
        for _ in range(15):
            text = await self.read_until(ready, self.timeout)
            if CONFIG_DIALOG.search(text):
                self.send("no\r")
            elif POAP.search(text[-300:]):
                self.send("skip\r")
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
            elif NEW_PASSWORD.search(text):
                raise AuthError(
                    "The device logged in but demands a new password (FTD does this when the day-0 "
                    "AdminPassword is weak or a dictionary word). Rebuild with a strong, non-dictionary "
                    "password, or complete the change on the console and update the node's pyATS "
                    "password in CML."
                )
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
                if prompt.endswith(">") and (self.creds.os or "").lower() not in NO_ENABLE_OS:
                    prompt = await self._enable(prompt)
                self.prompt = prompt
                self.last_prompt = ""
                self.at_prompt = True
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

    def _cancel_pending(self) -> None:
        with contextlib.suppress(Exception):
            self.proc.stdin.write("\x03")

    async def logout(self) -> None:
        """Leave the device logged out: 'end' out of config modes, then 'exit' (IOS/NX-OS/FTD/Linux
        all end the login with it). If the last command didn't finish at a prompt (an error,
        timeout or pending question), Ctrl-C first and send nothing else unless a fresh prompt
        comes back, so a pending question is never answered. Best effort, never raises."""
        if not self.prompt:
            return
        prompt = self._prompt_re()
        in_config = "(config" in self.last_prompt
        self.prompt = ""
        with contextlib.suppress(Exception):
            if not self.at_prompt:
                self._cancel_pending()
                self.buffer = ""
                text = await self.read_until(lambda t: bool(prompt.search(t)), 3.0)
                m = prompt.search(text)
                in_config = bool(m and "(config" in m.group(0))
            if in_config:
                self.send("end\r")
                await self.read_until(lambda t: bool(prompt.search(t)), 3.0)
            self.send("exit\r")
            await self.drain(quiet=0.5, limit=2.0)
        self.at_prompt = False

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

    async def run(
        self,
        command: str,
        timeout: float | None = None,  # noqa: ASYNC109
        *,
        answer_questions: bool = False,
        interrupt_after: float | None = None,
    ) -> str:
        """Send one command and return its output (without the echo and the trailing prompt).

        If the command asks a question ('[confirm]', '[yes/no]:', 'Do you want to continue?',
        'Destination filename [x]?') and `answer_questions` is set, the affirmative/default answer is
        sent (auto_answer) and reading goes on; otherwise the question raises InvalidRequest instead
        of hanging until the timeout. `interrupt_after` sends Ctrl-C after that many seconds and
        returns what was printed (for commands that never end by themselves, like FTD 'ping system').
        A command that times out is interrupted with Ctrl-C so it doesn't keep running."""
        prompt = self._prompt_re()
        await self.drain()
        echo = command.strip()[:40]

        def after_echo(t: str) -> str | None:
            idx = t.find(echo) if echo else 0
            if idx < 0:
                return None
            nl = t.find("\n", idx)
            return None if nl < 0 else t[nl:]

        self.at_prompt = False
        self.send(command + "\r")
        answered = 0
        need_echo = True
        before = ""  # output up to each answered question

        def view(t: str) -> str | None:
            return after_echo(t) if need_echo else t

        def logged_out(r: str) -> bool:
            tail = r[-200:]
            return bool(
                LOGIN_LINE.search(tail) or PRESS_RETURN_LINE.search(tail) or CONFIG_DIALOG.search(tail)
            )

        sent = command.strip()
        refill_os = (self.creds.os or "").lower() in REFILL_OS

        def refilled(r: str) -> bool:
            """FTD re-typed the rejected command after the prompt: '... Syntax error ...\n> cmd'."""
            if not refill_os:
                return False
            m = REFILLED.search(r[-400:])
            if not m:
                return False
            line = m.group("line").rstrip()
            head = line[: -len(sent)].rstrip() if sent and line.endswith(sent) else ""
            return bool(head) and bool(prompt.search("\n" + head))

        def finished(t: str) -> bool:
            r = view(t)
            return r is not None and bool(
                prompt.search(r) or QUESTION.search(r[-120:]) or logged_out(r) or refilled(r)
            )

        while True:
            try:
                if interrupt_after is not None:
                    try:
                        text = await self.read_until(finished, interrupt_after)
                    except UpstreamTimeout:
                        self.proc.stdin.write("\x03")
                        interrupt_after = None
                        text = await self.read_until(finished, timeout or self.timeout)
                else:
                    text = await self.read_until(finished, timeout or self.timeout)
            except UpstreamTimeout:
                with contextlib.suppress(Exception):
                    self.proc.stdin.write("\x03")  # don't leave a runaway command on the console
                raise
            rest = view(text) or ""
            if prompt.search(rest):
                break
            if refilled(rest) and not await self._more_output(0.6):
                # clear the re-typed command (Ctrl-U) so it is never run by a later RETURN
                self.send("\x15")
                await self.drain(quiet=0.5, limit=3.0)
                # a RETURN now gives a fresh prompt; were the line not cleared, it could only repeat the
                # command FTD already rejected (another syntax error), never run something new
                self.send("\r")
                try:
                    await self.read_until(lambda t: bool(prompt.search(t)), 5)
                except UpstreamError:
                    self._cancel_pending()
                    raise UpstreamTimeout(
                        f"{self.safe(command)!r} was rejected and the console did not clear the re-typed "
                        "command; the line was cancelled with Ctrl-C"
                    ) from None
                head, _, refill = rest.rpartition("\n")
                rest = head + "\n" + refill.rstrip()[: -len(sent)].rstrip()  # the bare prompt
                break
            if logged_out(rest):
                # ordinary output can end a chunk in 'login:'; a real logout stays quiet
                if await self._more_output(LOGOUT_QUIET):
                    continue
                # the node rebooted, was wiped or logged the session out while the command ran:
                # log in again so the session stays usable, but never re-send the command
                self.prompt = ""
                self.last_prompt = ""
                try:
                    await self.wake()
                    state = "logged in again"
                except UpstreamError as e:
                    state = f"logging in again failed: {self.safe(str(e))[:120]}"
                raise SessionLost(
                    f"The console session ended while running {self.safe(command)!r} (the node rebooted, "
                    f"was wiped or logged out); {state}. Check the node and re-run the command."
                )
            # a question-like tail may just be a chunk boundary in ordinary output: only treat it as
            # a question if the device then stays quiet
            if await self._more_output(0.6):
                continue
            question = rest.strip().splitlines()[-1][-160:] if rest.strip() else "?"
            if not answer_questions:
                # cancel it, so nothing (e.g. the next session's RETURN) confirms it later
                self.proc.stdin.write("\x03")
                with contextlib.suppress(UpstreamError):
                    await self.read_until(lambda t: bool(prompt.search(t)), 10)
                raise InvalidRequest(
                    f"{self.safe(command)!r} asked {self.safe(question)!r}; it was cancelled. Pass "
                    "answer_questions=true to cml_configure_node to answer it."
                )
            answered += 1
            if answered > 5:
                self._cancel_pending()
                raise InvalidRequest(
                    f"{self.safe(command)!r} kept asking questions (last: {self.safe(question)!r})"
                )
            before += rest
            need_echo = False
            self.send(auto_answer(question) + "\r")
        rest = before + rest
        lines = rest.split("\n")
        if lines and prompt.search("\n" + lines[-1]):
            self.last_prompt = lines[-1].strip()
            lines = lines[:-1]
        self.at_prompt = True
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
        lock_wait: float = 60.0,
    ) -> None:
        self.host = urlparse(url).hostname or ""
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.known_hosts = known_hosts
        self.lock_wait = lock_wait
        self._locks: dict[str, asyncio.Lock] = {}
        self._holders: dict[str, tuple[str, float]] = {}
        self._warned = False

    def lock(self, node_id: str) -> asyncio.Lock:
        """The node's console lock (one session per node per process)."""
        return self._locks.setdefault(node_id, asyncio.Lock())

    @contextlib.asynccontextmanager
    async def claim(self, node_id: str, label: str, purpose: str) -> AsyncIterator[None]:
        """Hold the node's console for one session. Waits up to `lock_wait` seconds for another call
        on the same node to finish, then raises ConsoleBusy instead of interleaving output.
        Sessions in other server processes are not coordinated."""
        lock = self.lock(node_id)
        try:
            await asyncio.wait_for(lock.acquire(), self.lock_wait)
        except TimeoutError:
            holder = self._holders.get(node_id)
            held = f"{holder[0]}, for {time.monotonic() - holder[1]:.0f}s" if holder else "another call"
            raise ConsoleBusy(
                f"The console of {label!r} is busy ({held}); waited {self.lock_wait:g}s. Retry when "
                "that call has finished."
            ) from None
        self._holders[node_id] = (purpose, time.monotonic())
        try:
            yield
        finally:
            self._holders.pop(node_id, None)
            lock.release()

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
        self.session: ConsoleSession | None = None

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
            text = await self._open(session)
            if "Escape character" not in text and "not found" in text.lower():
                # The console server lists only the account's own labs until 'all' is toggled; a
                # non-admin account needs that for labs shared with it (verified on CML 2.10).
                session.buffer = ""
                session.send("all\n")
                with contextlib.suppress(UpstreamTimeout):
                    await session.read_until(lambda t: "showing" in t.lower(), min(s.timeout, 5.0))
                text = await self._open(session)
            if "Escape character" not in text:
                detail = session.redact(text.strip()[-200:])
                raise InvalidRequest(
                    f"The console server could not open {self.target}: {detail}. Check that the node is "
                    "started; a non-admin account also needs the lab_exec permission on the lab (lab_view "
                    "alone does not open consoles, see docs/least-privilege.md)."
                )
            self.session = session
            await session.wake()
            return session
        except BaseException:
            await self._close()
            raise

    async def _open(self, session: ConsoleSession) -> str:
        session.buffer = ""
        session.send(f"open {self.target}\n")
        return await session.read_until(
            lambda t: "Escape character" in t or bool(re.search(r"not found|error|invalid", t, re.I)),
            self.server.timeout,
        )

    async def __aexit__(self, *exc: object) -> None:
        try:
            if self.session is not None and not isinstance(exc[1], asyncio.CancelledError | Unreachable):
                async with asyncio.timeout(10):
                    await self.session.logout()
        except Exception:
            pass  # logout is best effort; the connection is closed below either way
        finally:
            await self._finish()

    async def _finish(self) -> None:
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
