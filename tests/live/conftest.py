from pathlib import Path
from typing import Any

import pytest

from cml_mcp._core.testing import live_settings
from cml_mcp.config import Settings

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings() -> Settings:
    return live_settings(Settings, "CML_", _env_file=ROOT / ".env", mcp_cache_dir="")


def rw(settings: Settings, **kw: Any) -> Settings:
    return settings.model_copy(update={"mcp_enable_writes": True, **kw})
