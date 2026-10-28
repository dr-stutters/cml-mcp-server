"""#108: cml_archive_lab / cml_extract_node_configs leave out nodes whose definition has no config extraction.

CML only extracts definitions with `pyats.config_extract_command` (node_definition_iol_xe.json: 'show run');
node_definition_alpine.json (GET /node_definitions/alpine as live) has `pyats: {os: linux}` and CML answers
its PUT .../extract_configuration with 400 'Configuration Extraction not supported for Node <id>'.
"""

import copy
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from cml_mcp._core import ValidationFailed
from cml_mcp.extract import can_extract, extract_error

from .conftest import LID, NODE_CONFIGS, NODES, R1, R2, fixture
from .test_archive_lab import preview_only
from .test_write_tools import preview_apply

RW = {"mcp_enable_writes": True}


def as_alpine(nodes: list[dict[str, Any]], *ids: str) -> list[dict[str, Any]]:
    out = copy.deepcopy(nodes)
    for n in out:
        if n["id"] in ids:
            n["node_definition"] = "alpine"
            n["image_definition"] = None
    return out


@pytest.fixture
def mixed_api(lab_api: respx.MockRouter) -> respx.MockRouter:
    """r1 an IOL router, r2 an alpine host; both BOOTED."""
    return _with_alpine(lab_api, R2)


def _with_alpine(api: respx.MockRouter, *ids: str) -> respx.MockRouter:
    plain, full = as_alpine(NODES, *ids), as_alpine(NODE_CONFIGS, *ids)
    api.get(f"/labs/{LID}/nodes").mock(
        side_effect=lambda r: httpx.Response(
            200, json=plain if r.url.params.get("exclude_configurations") == "true" else full
        )
    )
    api.get("/node_definitions/alpine").mock(
        return_value=httpx.Response(200, json=fixture("node_definition_alpine.json"))
    )
    for nid in (R1, R2):
        api.put(f"/labs/{LID}/nodes/{nid}/extract_configuration").mock(
            return_value=httpx.Response(200, json=nid)
        )
    return api


def puts(api: respx.MockRouter) -> list[str]:
    return [c.request.url.path.split("/")[-2] for c in api.calls if c.request.method == "PUT"]


def test_can_extract_reads_the_pyats_block() -> None:
    import yaml

    assert can_extract(yaml.safe_load(fixture("node_definition_iol_xe.json")))
    assert not can_extract(yaml.safe_load(fixture("node_definition_alpine.json")))
    assert can_extract(None)  # unreadable: no check, CML decides


def test_extract_error_keeps_cmls_reason() -> None:
    path = f"/api/v0/labs/{LID}/nodes/{R2}/extract_configuration"
    unsupported = ValidationFailed(
        f"CML rejected the request (400) on PUT {path}: Configuration Extraction not supported for Node {R2}",
        400,
    )
    assert "not supported" in extract_error(unsupported)
    busy = ValidationFailed(f"CML rejected the request (400) on PUT {path}: " + "console busy " * 10, 400)
    msg = extract_error(busy)
    assert msg.startswith("CML rejected the request (400): console busy") and R2 not in msg
    assert len(extract_error(Exception("x" * 900))) == 500


async def test_extract_preview_skips_alpine(mixed_api: respx.MockRouter) -> None:
    preview, applied = await preview_apply("cml_extract_node_configs", {"lab": LID}, **RW)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["nodes"] == ["r1"]
    assert preview["preview"]["skipped_no_extract"] == {"r2": "definition alpine has no config extraction"}
    assert preview["blast_radius"] == 1
    assert any("1 node(s)" in s for s in preview["side_effects"])
    assert applied["result"] == {"saved": ["r1"]}
    assert puts(mixed_api) == [R1]


async def test_extract_blocked_when_no_node_supports_it(lab_api: respx.MockRouter) -> None:
    _with_alpine(lab_api, R1, R2)
    preview = await preview_only("cml_extract_node_configs", {"lab": LID}, **RW)
    assert preview["status"] == "blocked"
    assert "supports config extraction" in preview["blockers"][0]
    assert set(preview["preview"]["skipped_no_extract"]) == {"r1", "r2"}
    # one definition read for two nodes on it
    assert sum(c.request.url.path.endswith("/node_definitions/alpine") for c in lab_api.calls) == 1
    assert not puts(lab_api)


async def test_extract_iol_only_lab_unchanged(lab_api: respx.MockRouter) -> None:
    preview = await preview_only("cml_extract_node_configs", {"lab": LID}, **RW)
    assert preview["preview"]["nodes"] == ["r1", "r2"] and "skipped_no_extract" not in preview["preview"]
    assert preview["blast_radius"] == 2
    assert sum(c.request.url.path.endswith("/node_definitions/iol-xe") for c in lab_api.calls) == 1


async def test_extract_reports_cml_400_reason(mixed_api: respx.MockRouter) -> None:
    mixed_api.get("/node_definitions/alpine").mock(return_value=httpx.Response(404, json={"code": 404}))
    mixed_api.put(f"/labs/{LID}/nodes/{R2}/extract_configuration").mock(
        return_value=httpx.Response(
            400, json={"code": 400, "description": f"Configuration Extraction not supported for Node {R2}"}
        )
    )
    preview, applied = await preview_apply("cml_extract_node_configs", {"lab": LID}, **RW)
    assert preview["preview"]["nodes"] == ["r1", "r2"]  # definition unreadable: CML decides
    res = applied["result"]
    assert res["saved"] == ["r1"]
    assert res["failed"]["r2"] == "CML: configuration extraction not supported for this node's definition"


async def test_archive_preview_skips_alpine(mixed_api: respx.MockRouter, tmp_path: Path) -> None:
    preview, applied = await preview_apply("cml_archive_lab", {"lab": LID}, **RW, archive_dir=str(tmp_path))
    assert preview["status"] == "preview", preview
    p = preview["preview"]
    assert p["extract_configs"] == ["r1"] and p["stored_config_only"] == ["r2"]
    assert p["no_config_extraction"] == {"r2": "definition alpine has no config extraction"}
    assert preview["blast_radius"] == 1
    assert any("1 node(s)" in s for s in preview["side_effects"])
    res = applied["result"]
    assert res["extracted"] == ["r1"] and "not_extracted" not in res
    assert puts(mixed_api) == [R1]
    readme = (Path(res["path"]) / "README.md").read_text()
    assert "| r2 | alpine | BOOTED | not extracted: definition alpine has no config extraction |" in readme


async def test_archive_all_alpine_changes_nothing(lab_api: respx.MockRouter, tmp_path: Path) -> None:
    _with_alpine(lab_api, R1, R2)
    preview, applied = await preview_apply("cml_archive_lab", {"lab": LID}, **RW, archive_dir=str(tmp_path))
    assert preview["preview"]["extract_configs"] == []
    assert preview["blast_radius"] == 0
    assert not any("Overwrites" in s for s in preview["side_effects"])
    assert applied["result"]["extracted"] == [] and not puts(lab_api)
