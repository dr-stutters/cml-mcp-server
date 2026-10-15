"""Recipe verification against the real labs (L3). Marked `live` and `live_recipes`.

Only labs that are already running are verified: this suite never starts or stops a recipe lab
(other sessions may be using them). Bring one up first with `scripts/recipes.py swap <recipe>`.

    uv run pytest -m live_recipes tests/live/test_live_recipes.py
"""

import pytest
from stutters_mcp_core.testing import call_tool

from cml_mcp.config import Settings
from cml_mcp.recipes import get_recipe, recipe_names
from cml_mcp.server import create_server

pytestmark = [pytest.mark.live, pytest.mark.live_recipes]


@pytest.mark.parametrize("recipe", recipe_names())
async def test_recipe_verifies(settings: Settings, recipe: str) -> None:
    server = create_server(settings)
    title = get_recipe(recipe)["build"]["title"]
    labs = await call_tool(server, "cml_list_labs", {"response_format": "json", "limit": 500})
    row = next((r for r in labs["results"] if r.get("title") == title), None)
    if not row or row.get("state") != "STARTED":
        pytest.skip(f"{title} is not running ({row.get('state') if row else 'not built'})")
    result = await call_tool(server, "cml_verify_recipe", {"recipe": recipe})
    failed = [c for c in result["checks"] if not c["ok"]]
    assert result["passed"], failed
