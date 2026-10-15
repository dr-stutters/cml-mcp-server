"""L2: licence planner, recipes package, cml_plan_licences."""

from typing import Any

import httpx
import respx
from stutters_mcp_core.testing import call_tool

from cml_mcp.licence import capacity_from_licensing, licence_blocker, plan_stops, preferred_to_stop
from cml_mcp.recipes import get_recipe, recipe_for_lab, recipe_licensed_nodes, recipe_names
from cml_mcp.server import create_server

from .conftest import make_settings


def lab(i: str, running: int, preferred: bool = True) -> dict[str, Any]:
    return {"id": i, "title": i, "running": running, "preferred": preferred}


def test_plan_free() -> None:
    assert plan_stops([lab("a", 2)], needed=2, free=3) == []


def test_plan_swap_one_prefers_fewest_labs_then_ours_then_least_waste() -> None:
    labs = [lab("a", 1), lab("b", 2), lab("c", 3, preferred=False), lab("d", 2)]
    # need 2 more: one lab of 2 beats two labs of 1+1; b/d tie -> either, and never the foreign 3
    stops = plan_stops(labs, needed=2, free=0)
    assert stops is not None and len(stops) == 1 and stops[0]["title"] in {"b", "d"}
    # need 3: c alone (foreign) vs b+a (two labs): fewest labs wins
    assert [s["title"] for s in plan_stops(labs, needed=3, free=0) or []] == ["c"]


def test_plan_prefers_own_labs_at_equal_size() -> None:
    labs = [lab("theirs", 2, preferred=False), lab("ours", 2)]
    assert [s["title"] for s in plan_stops(labs, needed=2, free=0) or []] == ["ours"]


def test_plan_impossible_and_excludes_target() -> None:
    assert plan_stops([lab("a", 1)], needed=3, free=1) is None
    # the target's own running nodes are never a candidate
    assert plan_stops([lab("t", 4), lab("a", 1)], needed=1, free=0, exclude="t") == [lab("a", 1)]
    assert plan_stops([lab("t", 4)], needed=1, free=0, exclude="t") is None


def test_preferred_to_stop() -> None:
    assert preferred_to_stop({"lab_title": "mcp-cml-ise"})
    assert preferred_to_stop({"lab_title": "x", "lab_description": "foo (cml-mcp-server recipe ftd-fmc)"})
    assert not preferred_to_stop({"lab_title": "customer demo"})


def test_blocker_names_the_plan() -> None:
    usage = {
        "running_licensed_nodes": 5,
        "by_lab": {"mcp-cml-catc": 2, "mcp-cml-ftd": 1, "mcp-test-seed": 2},
        "labs": [lab("mcp-cml-catc", 2), lab("mcp-cml-ftd", 1), lab("mcp-test-seed", 2)],
        "limit": 5,
        "free": 0,
    }
    text = licence_blocker(usage, 2) or ""
    assert "only 0 of 5" in text and ("Stop 'mcp-cml-catc' (2)" in text or "Stop 'mcp-test-seed' (2)" in text)
    assert "Not possible" in (licence_blocker(usage, 6) or "")


def test_recipes_package() -> None:
    assert {"ftd-fmc", "catc-routers", "ise-access"} <= set(recipe_names())
    assert recipe_licensed_nodes(get_recipe("ise-access")) == 2
    assert recipe_licensed_nodes(get_recipe("ftd-fmc")) == 1
    assert recipe_for_lab("mcp-cml-catc") == "catc-routers"


def _cml(api: respx.MockRouter) -> None:
    labs = [
        {"id": "L-catc", "lab_title": "mcp-cml-catc", "state": "STARTED"},
        {"id": "L-seed", "lab_title": "mcp-test-seed", "state": "STARTED"},
        {"id": "L-ise", "lab_title": "mcp-cml-ise", "state": "STOPPED"},
    ]
    nodes = [
        {"id": "c1", "lab_id": "L-catc", "state": "BOOTED", "node_definition": "cat8000v"},
        {"id": "c2", "lab_id": "L-catc", "state": "BOOTED", "node_definition": "cat8000v"},
        {"id": "s1", "lab_id": "L-seed", "state": "BOOTED", "node_definition": "iol-xe"},
        {"id": "s2", "lab_id": "L-seed", "state": "BOOTED", "node_definition": "iol-xe"},
        {"id": "s3", "lab_id": "L-seed", "state": "BOOTED", "node_definition": "alpine"},
        {"id": "x", "lab_id": "L-catc", "state": "BOOTED", "node_definition": "external_connector"},
    ]
    ise_nodes = [
        {
            "id": "i1",
            "lab_id": "L-ise",
            "state": "STOPPED",
            "node_definition": "cat9000v-uadp",
            "label": "sw1",
        },
        {"id": "i2", "lab_id": "L-ise", "state": "STOPPED", "node_definition": "alpine", "label": "client"},
        {"id": "i3", "lab_id": "L-ise", "state": "STOPPED", "node_definition": "external_connector"},
    ]
    api.get("/labs").mock(return_value=httpx.Response(200, json=labs))
    api.get("/nodes").mock(return_value=httpx.Response(200, json=nodes))
    api.get("/labs/L-ise/nodes").mock(return_value=httpx.Response(200, json=ise_nodes))


async def test_plan_licences_tool_swap(api: respx.MockRouter) -> None:
    _cml(api)
    data = await call_tool(
        create_server(make_settings(node_license_limit=5)), "cml_plan_licences", {"target": "ise-access"}
    )
    assert data["needed_to_start"] == 2 and data["licences"]["free"] == 0
    assert data["plan"]["feasible"] is True
    assert [s["title"] for s in data["plan"]["stop"]] == ["mcp-cml-catc"]  # 2 nodes, exactly enough


async def test_plan_licences_tool_unbuilt_recipe_and_unknown_limit(api: respx.MockRouter) -> None:
    _cml(api)
    data = await call_tool(
        create_server(make_settings(node_license_limit=5)), "cml_plan_licences", {"target": "ftd-fmc"}
    )
    assert data["lab"]["exists"] is False and data["needed_to_start"] == 1
    assert len(data["plan"]["stop"]) == 1
    api.get("/licensing").mock(return_value=httpx.Response(500, json={"code": 500, "description": "x"}))
    data = await call_tool(create_server(make_settings()), "cml_plan_licences", {"target": "ftd-fmc"})
    assert "CML_NODE_LICENSE_LIMIT" in data["plan"]["summary"]


ENTERPRISE = {
    "features": [
        {
            "id": "regid.2019-10.com.cisco.CML_ENT_BASE,1.0_15d3",
            "description": "Cisco Modeling Labs - Enterprise License with 20 nodes capacity included",
            "in_use": 1,
            "status": "IN_COMPLIANCE",
        },
        {
            "id": "regid.2019-10.com.cisco.CML_NODE_COUNT,1.0_2607",
            "description": "Cisco Modeling Labs - Expansion node capacity for CML Enterprise Servers",
            "in_use": 50,
            "status": "IN_COMPLIANCE",
        },
    ],
    "authorization": {"status": "IN_COMPLIANCE"},
}
EVAL = {
    "features": [
        {
            "id": "regid.2020-02.com.cisco.CML_PER_BASE,1.0_bf11",
            "description": "Cisco Modeling Labs - Personal License with 20 nodes capacity included",
            "in_use": 1,
            "status": "EVAL",
        }
    ]
}


def test_capacity_from_licensing() -> None:
    assert capacity_from_licensing(ENTERPRISE) == (70, "CML_ENT_BASE 20 + CML_NODE_COUNT 50")
    assert capacity_from_licensing(EVAL)[0] == 5
    personal = {"features": [{**EVAL["features"][0], "status": "IN_COMPLIANCE"}]}
    assert capacity_from_licensing(personal) == (20, "CML_PER_BASE 20")
    plus = {
        "features": [
            {"id": "x.com.cisco.CML_PER_PLUS_BASE,1", "description": "", "in_use": 1, "status": "AUTHORIZED"}
        ]
    }
    assert capacity_from_licensing(plus)[0] == 40
    assert capacity_from_licensing({"features": []})[0] is None
    # an out-of-compliance expansion isn't counted
    lapsed = {
        "features": [ENTERPRISE["features"][0], {**ENTERPRISE["features"][1], "status": "OUT_OF_COMPLIANCE"}]
    }
    assert capacity_from_licensing(lapsed)[0] == 20


async def test_plan_detects_enterprise_capacity(api: respx.MockRouter) -> None:
    _cml(api)
    api.get("/licensing").mock(return_value=httpx.Response(200, json=ENTERPRISE))
    data = await call_tool(create_server(make_settings()), "cml_plan_licences", {"target": "ise-access"})
    assert data["licences"]["limit"] == 70 and data["licences"]["free"] == 65
    assert data["plan"]["summary"] == "Enough licences are free."
    # the setting still overrides detection
    data = await call_tool(
        create_server(make_settings(node_license_limit=4)), "cml_plan_licences", {"target": "ise-access"}
    )
    assert data["licences"]["limit"] == 4 and data["licences"]["limit_source"] == "CML_NODE_LICENSE_LIMIT"


def test_plan_scales_and_needs_many_labs() -> None:
    import time

    labs = [lab(f"l{i:02}", 1, preferred=i % 2 == 0) for i in range(30)]
    t = time.monotonic()
    stops = plan_stops(labs, needed=20, free=0)
    assert time.monotonic() - t < 1.0
    assert stops is not None and len(stops) == 20
    assert sum(not s["preferred"] for s in stops) == 5  # all 15 preferred labs first


def test_plan_least_waste_at_equal_rank() -> None:
    labs = [lab("big", 5), lab("fit", 3)]
    assert [s["title"] for s in plan_stops(labs, needed=3, free=0) or []] == ["fit"]


def test_capacity_edge_cases() -> None:
    # registered controller with an unused feature still in EVAL: not evaluation mode
    unused_eval = {
        "features": [
            *ENTERPRISE["features"],
            {"id": "x.com.cisco.CML_PER_BASE,1", "in_use": 0, "status": "EVAL"},
        ],
        "authorization": {"status": "IN_COMPLIANCE"},
    }
    assert capacity_from_licensing(unused_eval)[0] == 70
    authorized_expansion = {
        "features": [ENTERPRISE["features"][0], {**ENTERPRISE["features"][1], "status": "AUTHORIZED"}],
    }
    assert capacity_from_licensing(authorized_expansion)[0] == 70
    junk = {"features": [ENTERPRISE["features"][0], {**ENTERPRISE["features"][1], "in_use": "lots"}]}
    assert capacity_from_licensing(junk)[0] == 20
    assert capacity_from_licensing({"features": [], "authorization": {"status": "EVAL"}})[0] == 5


async def test_unknown_limit_is_not_cached(api: respx.MockRouter) -> None:
    from cml_mcp.client import CmlApp
    from cml_mcp.licence import node_limit

    route = api.get("/licensing")
    route.mock(return_value=httpx.Response(200, json={"features": []}))
    app = CmlApp(make_settings())
    assert (await node_limit(app))[0] is None
    route.mock(return_value=httpx.Response(200, json=ENTERPRISE))
    assert (await node_limit(app))[0] == 70
    route.mock(return_value=httpx.Response(200, json=EVAL))
    assert (await node_limit(app))[0] == 70  # cached
    app.node_limit_cache = None
    assert (await node_limit(app))[0] == 5
