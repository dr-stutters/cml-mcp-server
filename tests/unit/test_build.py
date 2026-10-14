import pytest

from cml_mcp.build import BuildError, NodeSpec, build_topology, parse_link

from .conftest import fixture

DEFS = {d["id"]: d for d in fixture("simplified_node_definitions.json")}


def test_parse_link_forms() -> None:
    assert parse_link("r1 r2") == (("r1", None), ("r2", None))
    assert parse_link("r1:Ethernet0/1<->r2") == (("r1", "Ethernet0/1"), ("r2", None))
    with pytest.raises(BuildError):
        parse_link("r1")


def test_build_allocates_interfaces_in_order() -> None:
    nodes = [
        NodeSpec(label="r1", definition="iol-xe", config="hostname r1"),
        NodeSpec(label="sw", definition="ioll2-xe"),
    ]
    topo, wiring = build_topology("t", nodes, ["r1 sw", "r1:Ethernet1/0 sw"], DEFS)
    assert wiring == ["r1:Ethernet0/0<->sw:Ethernet0/0", "r1:Ethernet1/0<->sw:Ethernet0/1"]
    r1 = topo["nodes"][0]
    labels = [i["label"] for i in r1["interfaces"]]
    # loopback + physical up to the highest one used (Ethernet1/0 is the 5th)
    assert labels == ["Loopback0", "Ethernet0/0", "Ethernet0/1", "Ethernet0/2", "Ethernet0/3", "Ethernet1/0"]
    assert r1["configuration"] == [{"name": "Main", "content": "hostname r1"}]
    link = topo["links"][1]
    assert link["n1"] == "n0" and link["i1"] == "i5"
    assert topo["lab"]["title"] == "t"


@pytest.mark.parametrize(
    ("nodes", "links", "message"),
    [
        ([NodeSpec(label="r1", definition="nope")], [], "unknown node definition"),
        (
            [NodeSpec(label="r1", definition="iol-xe"), NodeSpec(label="r1", definition="iol-xe")],
            [],
            "Duplicate",
        ),
        ([NodeSpec(label="r1", definition="iol-xe")], ["r1 r9"], "no node labelled 'r9'"),
        ([NodeSpec(label="r1", definition="iol-xe")], ["r1 r1"], "both ends"),
        (
            [NodeSpec(label="a", definition="iol-xe"), NodeSpec(label="b", definition="iol-xe")],
            ["a:Gi0/0 b"],
            "has no interface 'Gi0/0'",
        ),
        (
            [NodeSpec(label="a", definition="iol-xe"), NodeSpec(label="b", definition="iol-xe")],
            ["a:Ethernet0/0 b", "a:Ethernet0/0 b"],
            "used twice",
        ),
        ([NodeSpec(label="a", definition="iol-xe", image="bogus")], [], "does not belong"),
    ],
)
def test_build_errors(nodes: list[NodeSpec], links: list[str], message: str) -> None:
    with pytest.raises(BuildError, match=message):
        build_topology("t", nodes, links, DEFS)


def test_build_runs_out_of_interfaces() -> None:
    nodes = [
        NodeSpec(label="h", definition="alpine"),
        NodeSpec(label="s1", definition="unmanaged_switch"),
        NodeSpec(label="s2", definition="unmanaged_switch"),
    ]
    alpine_ports = len(DEFS["alpine"]["device"]["interfaces"]["physical"])
    links = [f"h s{1 + i % 2}" for i in range(alpine_ports + 1)]
    with pytest.raises(BuildError, match="no free interfaces"):
        build_topology("t", nodes, links, DEFS)


def test_explicit_interfaces_reserved_before_auto() -> None:
    nodes = [NodeSpec(label="a", definition="iol-xe"), NodeSpec(label="b", definition="iol-xe")]
    _, wiring = build_topology("t", nodes, ["a b", "a:Ethernet0/0 b:Ethernet0/0"], DEFS)
    assert wiring == ["a:Ethernet0/1<->b:Ethernet0/1", "a:Ethernet0/0<->b:Ethernet0/0"]


def test_label_rejects_spaces() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NodeSpec(label="r 1", definition="iol-xe")
