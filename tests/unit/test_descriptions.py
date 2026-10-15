"""L29: what a tool description says about a default matches the schema's default."""

import re

from fastmcp import Client

from cml_mcp.server import create_server

from .conftest import make_settings

DEFAULT_WORD = re.compile(r"\(default:? (true|false)\)", re.I)
DEFAULT_CHOICE = re.compile(r"'([\w-]+)' \(default\)")


async def test_descriptions_state_the_real_defaults() -> None:
    srv = create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))
    wrong = []
    async with Client(srv) as c:
        for tool in await c.list_tools():
            for name, prop in (tool.inputSchema.get("properties") or {}).items():
                text = str(prop.get("description") or "")
                if "default" not in prop:
                    continue
                if (m := DEFAULT_WORD.search(text)) and str(prop["default"]).lower() != m.group(1).lower():
                    wrong.append(f"{tool.name}.{name}: says {m.group(1)}, is {prop['default']}")
                if (m := DEFAULT_CHOICE.search(text)) and prop["default"] != m.group(1):
                    wrong.append(f"{tool.name}.{name}: says {m.group(1)!r}, is {prop['default']!r}")
    assert not wrong, wrong
