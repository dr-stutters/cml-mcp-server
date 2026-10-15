"""Settings: CML_* for the controller, MCP_* for this server (see stutters_mcp_core.settings)."""

import re
import ssl
from pathlib import Path
from typing import Self

from pydantic import Field, model_validator
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
    # Seconds a console call waits for another call on the same node to finish before it reports
    # the console as busy (one session per node per server process).
    console_lock_wait: float = Field(default=60.0, ge=0, description="CML_CONSOLE_LOCK_WAIT")

    # Running licensed-node cap. Detected from GET /licensing when unset (base licence nodes plus
    # CML_NODE_COUNT expansion; 5 in evaluation mode); set it to override the detection.
    # Start/build previews refuse to start more licensed nodes than are free.
    node_license_limit: int | None = Field(default=None, ge=1, description="CML_NODE_LICENSE_LIMIT")

    # Recipes carry ${LAB_*} placeholders instead of lab passwords/keys/communities. They are filled at
    # build/verify time from LAB_* environment variables, else from this dotenv-style file (never logged
    # or returned by tools).
    lab_secrets_file: str | None = Field(default=None, description="CML_LAB_SECRETS_FILE")

    # Image upload (L19): the only directory cml_upload_image reads from (streamed, never sent via MCP)
    image_dir: str | None = Field(default=None, description="CML_IMAGE_DIR")

    # Safety rails (L20, docs/safety.md). Comma-separated lab title globs or lab ids.
    protected_labs: str | None = Field(default=None, description="CML_PROTECTED_LABS")
    managed_labs: str | None = Field(default=None, description="CML_MANAGED_LABS")
    # cml_configure_node deny-list: the built-in destructive commands plus one extra regex
    config_deny_defaults: bool = Field(default=True, description="CML_CONFIG_DENY_DEFAULTS")
    config_deny: str | None = Field(default=None, description="CML_CONFIG_DENY")
    # With CML_CA_BUNDLE holding the controller's own (self-signed) certificate, the certificate is pinned and
    # its host name may differ from CML_URL (e.g. CN=cml-controller, URL by IP): set this to false then.
    tls_check_hostname: bool = Field(default=True, description="CML_TLS_CHECK_HOSTNAME")

    @model_validator(mode="after")
    def _hostname_check_needs_pinning(self) -> Self:
        if not self.tls_check_hostname:
            if self.ca_bundle is None:
                raise ValueError(
                    "CML_TLS_CHECK_HOSTNAME=false is only allowed with CML_CA_BUNDLE "
                    "(a pinned controller certificate)"
                )
            # a pin is one certificate: a CA bundle without host-name checks would accept any host it signs
            try:
                certs = Path(self.ca_bundle).read_text().count("-----BEGIN CERTIFICATE-----")
            except OSError as e:
                raise ValueError(f"CML_CA_BUNDLE can't be read: {e}") from e
            if certs != 1:
                raise ValueError(
                    "CML_TLS_CHECK_HOSTNAME=false needs CML_CA_BUNDLE to hold exactly one certificate (the "
                    f"controller's own, scripts/pin_controller.py); it holds {certs}"
                )
        if self.config_deny:
            from cml_mcp.safety import (
                deny_rule,  # local: safety imports the client, which imports this module
            )

            try:
                deny_rule(self.config_deny)
            except re.error as e:
                raise ValueError(f"CML_CONFIG_DENY is not a valid regular expression: {e}") from e
        return self

    def tls_verify(self) -> bool | ssl.SSLContext:
        """httpx `verify`: True/False, or a context for CML_CA_BUNDLE (without the host-name check when the
        bundle is the controller's own pinned certificate, CML_TLS_CHECK_HOSTNAME=false)."""
        if self.ca_bundle is None:
            return self.verify_ssl
        ctx = ssl.create_default_context(cafile=str(self.ca_bundle))
        if not self.tls_check_hostname:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # the pinned certificate may be a leaf
        return ctx
