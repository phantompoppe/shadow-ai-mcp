# Local development

```bash
cp .env.example .env
docker compose up --build
```

Compose exposes port 8000 only on the host loopback address. It runs PostgreSQL and one Shadow AI process; migrations run before service startup. The worker imports the mounted sample registry, SIEM, proxy, and gateway fixtures. The six tools are available at `http://127.0.0.1:8000/mcp`; the read-only investigation UI is at `http://127.0.0.1:8000/ui/`. `/healthz`, `/readyz`, and `/metrics` provide process, database, and scrape checks.

Without Docker, install Python 3.12+ and run:

```bash
uv venv
uv pip install -e '.[dev]'
SHAI_DATABASE_URL=sqlite:///shadow.db SHAI_DEVELOPMENT_MODE=true SHAI_AUTH_MODE=dev SHAI_UI_ENABLED=true \
  .venv/bin/shadow-ai demo
```

The demo command migrates, imports fixtures, detects, and starts HTTP. Open `/ui/` in a browser on the same machine. Stdio is explicit development mode: set `SHAI_TRANSPORT=stdio` and run `shadow-ai serve` after `shadow-ai demo`/`sync`. Never use dev identity on a network-facing production listener. See [README](../README.md) for MCP client calls, the [UI guide](ui.md), and [configuration](configuration.md) for real source mappings.

Check the code with `ruff format --check .`, `ruff check .`, `mypy src`, and `pytest -q`. A test uses the official MCP client in memory; an HTTP smoke test can connect to the local endpoint. The example data uses relative event times and `.test` destinations.
