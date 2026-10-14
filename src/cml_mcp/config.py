"""Settings: CML_* for the controller, MCP_* for this server (see stutters_mcp_core.settings)."""

from pydantic import Field
from stutters_mcp_core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CML_")

    # Seconds the lifecycle tools (start/stop, wait_for_converged) wait by default before giving up.
    wait_timeout: float = Field(default=600.0, gt=0, description="CML_WAIT_TIMEOUT")
