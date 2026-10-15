"""Image upload (L19): files from an allow-listed directory on the server host, streamed to CML as multipart.

The image never passes through the MCP payload: the caller names a file in CML_IMAGE_DIR, the server checks
it (inside the directory after resolving symlinks, a disk-image extension, size, SHA-256) and streams it to
`POST /images/upload` (multipart field `field0`, header `X-Original-File-Name`), which puts it in the
controller's drop folder. An image definition then makes it usable by a node definition.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import anyio
import httpx
from stutters_mcp_core import InvalidRequest, UpstreamError

from cml_mcp.client import CmlApp

# What CML's upload accepts (virl2_client EXTENSION_LIST, CML 2.10).
EXTENSIONS = (".qcow2", ".qcow", ".img", ".iso", ".tar", ".tar.gz", ".vmdk")
CHUNK = 1024 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")


def extension(name: str) -> str:
    return ".tar.gz" if name.endswith(".tar.gz") else Path(name).suffix


def check_name(name: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise InvalidRequest(f"Image name {name!r}: letters, digits, '.', '_', '+', '-' only (no paths)")
    if extension(name) not in EXTENSIONS:
        raise InvalidRequest(f"Image name {name!r}: the extension must be one of {', '.join(EXTENSIONS)}")


def resolve_image_file(image_dir: str | None, file: str) -> Path:
    """The file named `file` inside CML_IMAGE_DIR, refusing anything outside it (also via symlinks)."""
    if not image_dir:
        raise InvalidRequest(
            "Image upload is off: set CML_IMAGE_DIR to the directory on the server host that holds the "
            "images (the file is read there and streamed to CML, never sent through MCP)."
        )
    try:
        root = Path(os.path.expanduser(image_dir)).resolve()
        if not root.is_dir():
            raise InvalidRequest(f"CML_IMAGE_DIR {str(root)!r} is not a directory")
        candidate = (root / file).resolve()
        inside = candidate != root and root in candidate.parents
        is_file = inside and candidate.is_file()
    except (OSError, ValueError) as e:  # e.g. a NUL byte in the name
        raise InvalidRequest(f"Bad image file name {file!r}: {e}") from None
    if not inside:
        raise InvalidRequest(f"{file!r} is outside CML_IMAGE_DIR")
    if not is_file:
        raise InvalidRequest(f"No file {file!r} in CML_IMAGE_DIR (see cml_get_image_files)")
    return candidate


def file_identity(path: Path) -> tuple[int, int, int, int]:
    """(device, inode, size, mtime_ns) of the resolved file, read without following symlinks."""
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise InvalidRequest(f"{path.name!r} is not a regular file")
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


def list_image_files(image_dir: str | None) -> list[dict[str, Any]]:
    if not image_dir:
        return []
    root = Path(os.path.expanduser(image_dir)).resolve()
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and extension(p.name) in EXTENSIONS:
            rp = p.resolve()
            if rp == root or root in rp.parents:
                out.append({"file": str(p.relative_to(root)), "size_mb": round(p.stat().st_size / 2**20, 1)})
    return out


async def sha256_of(path: Path) -> str:
    def work() -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        return h.hexdigest()

    return await anyio.to_thread.run_sync(work)


def multipart(
    path: Path, name: str, identity: tuple[int, int, int, int] | None = None
) -> tuple[str, int, Any]:
    """(content type, exact length, async body) of a one-file multipart upload streamed from disk. The file
    is opened once without following symlinks; with `identity` (from the preview) a swapped or changed file
    is refused, and a file that grows or shrinks while streaming aborts the upload."""
    boundary = "cmlmcp" + secrets.token_hex(16)
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="field0"; filename="{name}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or (
        identity is not None and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != identity
    ):
        os.close(fd)
        raise InvalidRequest("The image file changed since the preview; preview again")
    size = st.st_size

    async def body() -> AsyncIterator[bytes]:
        sent = 0
        try:
            yield head
            while chunk := await anyio.to_thread.run_sync(os.read, fd, CHUNK):
                sent += len(chunk)
                if sent > size:
                    break
                yield chunk
        finally:
            os.close(fd)
        if sent != size:
            raise InvalidRequest(
                "The image file changed during the upload (size differs); nothing usable was sent"
            )
        yield tail

    return f"multipart/form-data; boundary={boundary}", len(head) + size + len(tail), body()


async def upload(
    app: CmlApp, path: Path, name: str, identity: tuple[int, int, int, int] | None = None
) -> Any:
    """Stream `path` to the controller's drop folder as `name`. A body can't be replayed, so the only retry is
    one fresh attempt after a 401 (expired login), which CML sends before reading the body."""
    timeout = httpx.Timeout(app.settings.timeout, read=max(600.0, app.settings.timeout))
    for attempt in (1, 2):
        ctype, length, body = multipart(path, name, identity)
        auth = await app.api.auth.headers(app.api)
        headers = {
            **auth,
            "Content-Type": ctype,
            "Content-Length": str(length),
            "X-Original-File-Name": name,
            "X-File-Name": name,
            "Accept": "application/json",
        }
        try:
            resp = await app.api.send_raw(
                "POST", "/images/upload", content=body, headers=headers, timeout=timeout
            )
        except UpstreamError as e:
            raise type(e)(
                f"{e} The upload may have left a partial file: check cml_get_image_files and remove it with "
                f"cml_delete_image(drop_file={name!r}) before retrying.",
                e.status_code,
            ) from None
        if resp.status_code == 401 and attempt == 1 and await app.api.auth.on_unauthorized(app.api, auth):
            continue
        if resp.status_code >= 400:
            raise app.api.error_from_response(resp)
        try:
            return resp.json()
        except ValueError:
            return resp.text.strip() or "OK"
    raise UpstreamError("CML refused the upload login twice")  # pragma: no cover


async def drop_folder(app: CmlApp) -> list[str]:
    data = await app.api.get("/list_image_definition_drop_folder")
    return [str(x) for x in data] if isinstance(data, list) else []


async def disk_free(app: CmlApp) -> int | None:
    try:
        stats = await app.api.get("/system_stats")
    except UpstreamError:
        return None
    frees = [
        c.get("stats", {}).get("disk", {}).get("free")
        for c in (stats.get("computes") or {}).values()
        if c.get("is_controller", True)
    ]
    frees = [f for f in frees if isinstance(f, int)]
    return min(frees) if frees else None
