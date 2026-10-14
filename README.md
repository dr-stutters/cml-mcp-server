# cml-mcp-server

MCP server for **Cisco Modeling Labs (CML 2.x)**, built on
[stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core).

> Status: in development (M3: write tools).

```bash
cp .env.example .env    # set CML_URL, CML_USERNAME, CML_PASSWORD
uv sync
uv run cml-mcp-server check     # connect and print cml_status
uv run cml-mcp-server           # stdio MCP server
```

Not affiliated with or endorsed by Cisco Systems, Inc.
