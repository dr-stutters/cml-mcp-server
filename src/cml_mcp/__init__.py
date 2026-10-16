"""MCP server for Cisco Modeling Labs (CML 2.x)."""

try:
    from cml_mcp._core import run_cli
except ModuleNotFoundError as e:  # a source tree or git checkout without the bundled core
    if e.name != "cml_mcp._core":
        raise
    raise ModuleNotFoundError(
        "cml_mcp._core is missing: this build doesn't bundle stutters-mcp-core (ADR-005). Install a release "
        "wheel, or run `python scripts/bundle_core.py vendor` in a clone first.",
        name=e.name,
    ) from None

from cml_mcp.config import Settings
from cml_mcp.preflight import preflight
from cml_mcp.server import SPEC, create_server


def main() -> None:
    run_cli(SPEC, Settings, create_server, preflight=preflight)


__all__ = ["SPEC", "Settings", "create_server", "main"]
