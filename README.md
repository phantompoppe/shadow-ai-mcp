# Shadow AI MCP

Read-only MCP investigation server for direct AI use, MCP gateway bypass, unapproved MCP servers, and expired approvals. The server stores normalized metadata and evidence references; raw prompts, responses, MCP arguments/results, and credentials stay in source systems. It is a self-hosted discovery service, not an enforcement system or dashboard.

## Open the fixture UI in a browser

[Open Shadow AI MCP in GitHub Codespaces](https://codespaces.new/phantompoppe/shadow-ai-mcp?quickstart=1) while signed in to the GitHub account with access to this private repository. Choose **Create codespace** if one is not already running. Codespaces installs the Python project, imports the fixture events, runs detections, and starts the UI automatically. Open the **Ports** tab, keep port **8000** set to **Private**, and click its forwarded address. The root address redirects to `/ui/`. This runs in GitHub's hosted development environment; nothing needs to be installed on your Mac. Stop the codespace when finished. Codespaces consumes your account's compute and storage allowance and may incur charges beyond the included quota. See [browser demo](docs/browser-demo.md) for troubleshooting and security boundaries.

To clone on a machine with Git and access to the private repository, paste the URL directly:

```bash
git clone https://github.com/phantompoppe/shadow-ai-mcp.git
```

## Local demo

```bash
cp .env.example .env
docker compose up --build
# MCP: http://127.0.0.1:8000/mcp
# UI:  http://127.0.0.1:8000/ui/
# GET http://127.0.0.1:8000/healthz and /readyz
```

For a Python development environment without Docker:

```bash
uv venv && uv pip install -e '.[dev]'
SHAI_DATABASE_URL=sqlite:///shadow.db SHAI_DEVELOPMENT_MODE=true SHAI_AUTH_MODE=dev \
  SHAI_HOST=127.0.0.1 .venv/bin/shadow-ai demo
```

The SQLite path is for local development and tests; production requires PostgreSQL. For a Python-only UI demo, also set `SHAI_UI_ENABLED=true` before `shadow-ai demo`. `shadow-ai demo` migrates, loads fixtures, runs detections, and starts Streamable HTTP. `shadow-ai migrate`, `shadow-ai sync`, and `shadow-ai serve` separate those steps. The local demo has six source events, an approved proxy event, an approved gateway event, and a three-asset registry. A missing actor/device fixture demonstrates reduced confidence. See [local development](docs/local-development.md) and the [UI guide](docs/ui.md).

## MCP client configuration

Through an enterprise gateway, adapt this generic client configuration to your host's format. Supply the token at runtime; do not commit it:

```json
{
  "mcpServers": {
    "shadow-ai": {
      "url": "https://mcp-gateway.internal.example/shadow-ai/mcp",
      "headers": {"Authorization": "Bearer ${SHADOW_AI_TOKEN}"}
    }
  }
}
```

For local stdio development, set `SHAI_TRANSPORT=stdio`, `SHAI_DEVELOPMENT_MODE=true`, `SHAI_AUTH_MODE=dev`, and an explicit local database URL before running `shadow-ai serve`. The local Streamable HTTP demo is at `http://127.0.0.1:8000/mcp`.

## Example calls

The official Python SDK client can call all six tools. Use the actual `finding_id` returned by search and a UTC window covering your data:

```python
import asyncio
from datetime import datetime, timedelta, timezone
from mcp.client import Client


async def main():
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(hours=1)
    window = {"start_time": start.isoformat(), "end_time": end.isoformat()}
    async with Client("http://127.0.0.1:8000/mcp") as client:
        search = await client.call_tool("search_shadow_ai", {"limit": 10})
        finding_id = search.structured_content["findings"][0]["finding_id"]
        print(
            (
                await client.call_tool("get_shadow_ai_finding", {"finding_id": finding_id})
            ).structured_content
        )
        print(
            (
                await client.call_tool("explain_shadow_ai_finding", {"finding_id": finding_id})
            ).structured_content
        )
        print(
            (
                await client.call_tool(
                    "find_llm_proxy_bypass", {**window, "minimum_confidence": "low"}
                )
            ).structured_content
        )
        print(
            (
                await client.call_tool(
                    "find_mcp_gateway_bypass", {**window, "minimum_confidence": "low"}
                )
            ).structured_content
        )
        print(
            (
                await client.call_tool("check_ai_approval", {"asset_id": "ai-expired"})
            ).structured_content
        )


asyncio.run(main())
```

`search_shadow_ai` and the two range tools accept `cursor` from `next_cursor`. See the [tool reference](docs/mcp-tools.md) for filters, scopes, and safe errors.

## Checks

```bash
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
```

## Documentation

- [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), [connector development](docs/connector-development.md)
- [Configuration](docs/configuration.md), [data model](docs/data-model.md), [detections](docs/detections.md), [MCP tools](docs/mcp-tools.md)
- [Local development](docs/local-development.md), [production deployment](docs/production-deployment.md), [privacy and retention](docs/privacy-retention.md), [troubleshooting](docs/troubleshooting.md)
- [Investigation UI](docs/ui.md)

The provider catalog is illustrative. Domain-based detection is suggestive and needs corroborating identity, device, route, and source evidence for stronger confidence. Live SIEM, proxy, gateway, and registry HTTP endpoints require enterprise configuration and have not been verified by this fixture demo.
