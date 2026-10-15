"""Lab secrets never leave the server (L21): a FastMCP middleware that replaces every resolved LAB_* value
(from LAB_* env vars or CML_LAB_SECRETS_FILE, 6+ characters) with its ${LAB_*} reference in tool results and
errors. A recipe lab's day-0 configs hold the real values (they have to), so config reads, exports, console
output and upstream errors would otherwise return them."""

from __future__ import annotations

from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent

from cml_mcp.recipes import redact_values, secret_names_by_value


class LabSecretRedactor(Middleware):
    def __init__(self, secrets_file: str | None) -> None:
        self.secrets_file = secrets_file

    def mapping(self) -> dict[str, str]:
        # re-read per call: cheap (a small dotenv file), and picks up rotated values without a restart
        return secret_names_by_value(self.secrets_file)

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        mapping = self.mapping()
        try:
            result = await call_next(context)
        except Exception as e:
            message = str(e)
            clean = redact_values(message, mapping)
            if clean == message:
                raise
            raise ToolError(clean) from None
        if not mapping or not isinstance(result, ToolResult):
            return result
        content = [
            c.model_copy(update={"text": redact_values(c.text, mapping)}) if isinstance(c, TextContent) else c
            for c in result.content
        ]
        structured = redact_values(result.structured_content, mapping) if result.structured_content else None
        return ToolResult(content=content, structured_content=structured, meta=result.meta)
