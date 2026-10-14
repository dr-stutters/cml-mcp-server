"""Settings: CML_* for the controller, MCP_* for this server (see stutters_mcp_core.settings)."""

from pydantic import Field
from stutters_mcp_core import BaseServerSettings, server_config


class Settings(BaseServerSettings):
    model_config = server_config("CML_")

    # Seconds the lifecycle tools (start/stop, wait_for_converged) wait by default before giving up.
    wait_timeout: float = Field(default=600.0, gt=0, description="CML_WAIT_TIMEOUT")

    # Console server (SSH on the controller) used by cml_run_commands / cml_configure_node.
    console_port: int = Field(default=22, ge=1, le=65535, description="CML_CONSOLE_PORT")
    # known_hosts file for the console server's SSH host key. When unset, the key is checked against
    # ~/.ssh/known_hosts if CML_VERIFY_SSL is true, and not checked when it is false (lab default).
    console_known_hosts: str | None = Field(default=None, description="CML_CONSOLE_KNOWN_HOSTS")
