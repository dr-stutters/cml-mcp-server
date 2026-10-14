"""Helpers for live tests: build and tear down throwaway 'mcp-test-*' labs with the raw API."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from cml_mcp.client import CmlApp
from cml_mcp.config import Settings

TWO_ROUTERS = """
lab:
  title: {title}
  description: created by cml-mcp-server live tests
  version: 0.3.0
nodes:
  - id: n0
    label: r1
    node_definition: iol-xe
    x: 0
    y: 0
    configuration:
      - name: ios_config.txt
        content: |
          hostname r1
          interface Ethernet0/0
           ip address 10.99.0.1 255.255.255.0
           no shutdown
          end
    interfaces:
      - {{id: i0, label: Loopback0, type: loopback}}
      - {{id: i1, label: Ethernet0/0, type: physical, slot: 0}}
  - id: n1
    label: r2
    node_definition: iol-xe
    x: 200
    y: 0
    configuration:
      - name: ios_config.txt
        content: |
          hostname r2
          interface Ethernet0/0
           ip address 10.99.0.2 255.255.255.0
           no shutdown
          end
    interfaces:
      - {{id: i0, label: Loopback0, type: loopback}}
      - {{id: i1, label: Ethernet0/0, type: physical, slot: 0}}
links:
  - {{id: l0, n1: n0, n2: n1, i1: i1, i2: i1}}
"""


async def _create(settings: Settings, title: str, start: bool) -> str:
    app = CmlApp(settings)
    try:
        for lab in await app.list_labs():  # leftovers from an interrupted run
            if lab.get("lab_title") == title:
                await _destroy(app, lab["id"])
        res = await app.api.post(
            "/import",
            None,
            content=TWO_ROUTERS.format(title=title),
            headers={"Content-Type": "application/x-yaml"},
        )
        lab_id = str(res["id"])
        if start:
            await app.api.put(f"/labs/{lab_id}/start")
            deadline = time.monotonic() + 300
            while await app.api.get(f"/labs/{lab_id}/check_if_converged") is not True:
                if time.monotonic() > deadline:
                    raise TimeoutError("test lab did not converge")
                await asyncio.sleep(5)
        return lab_id
    finally:
        await app.aclose()


async def _destroy(app: CmlApp, lab_id: str) -> None:
    await app.api.put(f"/labs/{lab_id}/stop")
    await app.api.put(f"/labs/{lab_id}/wipe")
    await app.api.delete(f"/labs/{lab_id}")


async def _delete(settings: Settings, lab_id: str) -> None:
    app = CmlApp(settings)
    try:
        await _destroy(app, lab_id)
    except Exception:  # already gone
        pass
    finally:
        await app.aclose()


def create_lab(settings: Settings, title: str, *, start: bool = False) -> str:
    return asyncio.run(_create(settings, title, start))


def delete_lab(settings: Settings, lab_id: str) -> None:
    asyncio.run(_delete(settings, lab_id))


def raw(settings: Settings, method: str, path: str, **kw: Any) -> Any:
    async def go() -> Any:
        app = CmlApp(settings)
        try:
            return await app.api.request(method, path, **kw)
        finally:
            await app.aclose()

    return asyncio.run(go())


async def confirm_call(client: Any, name: str, args: dict[str, Any]) -> Any:
    """Preview then apply a write tool through an MCP client; returns the 'result' of the apply."""
    import json

    def body(res: Any) -> Any:
        return (
            res.structured_content if res.structured_content is not None else json.loads(res.content[0].text)
        )

    preview = body(await client.call_tool(name, args))
    assert preview["status"] == "preview", preview
    applied = body(await client.call_tool(name, {**args, "confirm": preview["confirm"]}))
    assert applied["status"] == "applied", applied
    return applied.get("result")


def find_lab(settings: Settings, title: str) -> str | None:
    async def go() -> str | None:
        app = CmlApp(settings)
        try:
            for lab in await app.list_labs():
                if lab.get("lab_title") == title:
                    return str(lab["id"])
            return None
        finally:
            await app.aclose()

    return asyncio.run(go())
