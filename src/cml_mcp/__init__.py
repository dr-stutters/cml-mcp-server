"""MCP server for Cisco Modeling Labs (CML 2.x)."""

from stutters_mcp_core import run_cli

from cml_mcp.config import Settings
from cml_mcp.server import SPEC, create_server


def main() -> None:
    run_cli(SPEC, Settings, create_server)


__all__ = ["SPEC", "Settings", "create_server", "main"]
