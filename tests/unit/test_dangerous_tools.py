import httpx
import respx

from .conftest import LID, LINK
from .test_write_tools import RWD, preview_apply

# --- dangerous ---------------------------------------------------------------------------


async def test_delete_lab_refuses_running_lab_without_force(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_delete_lab", {"lab": LID}, **RWD)
    assert preview["status"] == "blocked" and "force=true" in preview["blockers"][0]


async def test_delete_lab_force_stops_wipes_deletes(lab_api: respx.MockRouter) -> None:
    states = iter(["STOPPED", "DEFINED_ON_CORE"])
    lab_api.get(f"/labs/{LID}/state").mock(side_effect=lambda r: httpx.Response(200, json=next(states)))
    stop = lab_api.put(f"/labs/{LID}/stop").mock(return_value=httpx.Response(204))
    wipe = lab_api.put(f"/labs/{LID}/wipe").mock(return_value=httpx.Response(204))
    delete = lab_api.delete(f"/labs/{LID}").mock(return_value=httpx.Response(204))
    preview, applied = await preview_apply("cml_delete_lab", {"lab": LID, "force": True}, **RWD)
    assert "irreversible" in preview["side_effects"][0]
    assert stop.called and wipe.called and delete.called
    assert applied["result"] == {"deleted": LID}


async def test_delete_node_lists_links(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_delete_node", {"lab": LID, "node": "r2"}, **RWD)
    assert preview["status"] == "blocked"
    assert preview["preview"]["links_removed"] == ["r1:Ethernet0/0<->r2:Ethernet0/0"]


async def test_delete_link(lab_api: respx.MockRouter) -> None:
    route = lab_api.delete(f"/labs/{LID}/links/{LINK}").mock(return_value=httpx.Response(204))
    _, applied = await preview_apply("cml_delete_link", {"lab": LID, "link": "r1<->r2"}, **RWD)
    assert route.called and applied["result"]["deleted"] == "r1:Ethernet0/0<->r2:Ethernet0/0"


async def test_wipe_node_requires_stopped(lab_api: respx.MockRouter) -> None:
    preview, _ = await preview_apply("cml_wipe_node", {"lab": LID, "node": "r1"}, **RWD)
    assert preview["status"] == "blocked" and "stop it first" in preview["blockers"][0]
