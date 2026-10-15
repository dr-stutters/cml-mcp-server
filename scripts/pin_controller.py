"""Pin a CML controller's TLS certificate and console-server SSH host key (L20, docs/safety.md).

    uv run python scripts/pin_controller.py https://cml.example.com --out ~/.config/cml-mcp-server

Writes `<out>/cml-ca.pem` (the certificate the controller presents) and `<out>/cml-known_hosts` (its SSH host
keys on the console port), prints their SHA-256 fingerprints and the settings to use:

    CML_VERIFY_SSL=true
    CML_CA_BUNDLE=<out>/cml-ca.pem
    CML_TLS_CHECK_HOSTNAME=false   # only if the certificate doesn't name the CML_URL host (self-signed)
    CML_CONSOLE_KNOWN_HOSTS=<out>/cml-known_hosts

This is trust on first use: compare the printed fingerprints with the controller's (the certificate in the
CML UI, and `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub` on the controller) before relying on them. With a
certificate from a real CA, set CML_CA_BUNDLE to that CA instead and keep host-name checking on.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import ssl
import sys
from pathlib import Path
from urllib.parse import urlparse

import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding


def fetch_certificate(host: str, port: int) -> str:
    return ssl.get_server_certificate((host, port), timeout=15)


async def fetch_host_keys(host: str, port: int) -> list[str]:
    """The host keys the console server presents (no login is attempted)."""
    entry = host if port == 22 else f"[{host}]:{port}"
    lines: list[str] = []
    for alg in ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"):
        try:
            key = await asyncio.wait_for(
                asyncssh.get_server_host_key(host, port, server_host_key_algs=[alg]), 15
            )
        except (OSError, asyncssh.Error, TimeoutError):
            continue
        if key is not None:
            lines.append(f"{entry} {key.export_public_key('openssh').decode().strip()}")
    return lines


def name_matches(pattern: str, host: str) -> bool:
    """RFC 6125-style: exact (case-insensitive) or a single left-most wildcard label."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*.") and "." in host:
        return host.split(".", 1)[1] == pattern[2:]
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("url", help="controller URL, e.g. https://198.18.128.10")
    parser.add_argument("--out", default="~/.config/cml-mcp-server", help="directory for the pinned files")
    parser.add_argument("--console-port", type=int, default=22)
    args = parser.parse_args()
    u = urlparse(args.url)
    if not u.hostname:
        sys.exit("give the controller URL, e.g. https://cml.example.com")
    out = Path(os.path.expanduser(args.out))
    out.mkdir(parents=True, exist_ok=True)
    pem = fetch_certificate(u.hostname, u.port or 443)
    cert = x509.load_pem_x509_certificate(pem.encode())
    (out / "cml-ca.pem").write_text(pem)
    (out / "cml-ca.pem").chmod(0o600)
    keys = asyncio.run(fetch_host_keys(u.hostname, args.console_port))
    if not keys:
        print("!! could not read the console server's SSH host key", file=sys.stderr)
    (out / "cml-known_hosts").write_text("".join(k + "\n" for k in keys))
    (out / "cml-known_hosts").chmod(0o600)
    names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(n.value) for n in san]
    except x509.ExtensionNotFound:
        pass
    print(f"certificate: {cert.subject.rfc4514_string()}  names: {names or '-'}")
    print(f"  valid {cert.not_valid_before_utc:%Y-%m-%d} .. {cert.not_valid_after_utc:%Y-%m-%d}")
    print(
        f"  SHA-256 {':'.join(f'{b:02X}' for b in hashlib.sha256(cert.public_bytes(Encoding.DER)).digest())}"
    )
    for k in keys:
        key = asyncssh.import_public_key(k.split(" ", 1)[1])
        print(f"ssh host key: {key.get_algorithm()} {key.get_fingerprint('sha256')}")
    host_matches = any(name_matches(n, u.hostname) for n in names)
    print("\nSettings:")
    print("CML_VERIFY_SSL=true")
    print(f"CML_CA_BUNDLE={out / 'cml-ca.pem'}")
    if not host_matches:
        print(f"CML_TLS_CHECK_HOSTNAME=false   # the certificate doesn't name {u.hostname}")
    print(f"CML_CONSOLE_KNOWN_HOSTS={out / 'cml-known_hosts'}")
    print("\nCompare the fingerprints with the controller's before trusting them (trust on first use).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
