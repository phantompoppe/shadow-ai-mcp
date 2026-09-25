# Read-only investigation UI

Enable the optional UI with `SHAI_UI_ENABLED=true`. It is served from the existing process at `/ui/`; no front-end build service or separate database is required. The fixture demo enables it in `.env.example`. Production leaves it off unless explicitly configured.

The Findings view filters persisted detections by exact destination, detection ID, severity, and confidence. Counts describe **the current result page**, not the entire database. Select a row to see the deterministic explanation, routes, reason codes, evidence references, confidence limits, linked registry asset, and human investigation steps. The Approval registry view checks an ID, name, or endpoint. Telemetry health displays connector freshness and gaps. Pagination uses the same stable cursor as the MCP search tool.

Every `/ui/` request requires the configured authentication method and `shadow_ai:read`, including HTML and static assets. Searches and approval lookups use bounded JSON POST bodies for read-only queries, keeping filter values out of URL access logs. JSON queries call `InvestigationService.execute`, so result limits, evidence reference hashing, safe errors, and hashed filter audit records match MCP behavior. Raw source evidence is never fetched. `shadow_ai:evidence:read` allows source reference URIs; ordinary readers see hashes. The UI adds no write action.

For production browser access, configure a gateway or reverse proxy to authenticate the browser and forward either a signed gateway identity assertion or a bearer token to Shadow AI MCP. Strip untrusted identity headers before injection. Use HTTPS, restrict the origin, and do not expose development authentication. The bundled UI does not implement a browser sign-in or store tokens. Its JavaScript/CSS are same-origin, and responses use `no-store`, a restrictive Content Security Policy, and no third-party assets. Rendered telemetry uses DOM text nodes rather than HTML interpolation.

For the local Python demo:

```bash
uv venv && uv pip install -e '.[dev]'
SHAI_DATABASE_URL=sqlite:///shadow.db SHAI_DEVELOPMENT_MODE=true SHAI_AUTH_MODE=dev \
  SHAI_UI_ENABLED=true SHAI_HOST=127.0.0.1 .venv/bin/shadow-ai demo
# Open http://127.0.0.1:8000/ui/
```

The UI is an investigation aid. It does not change finding status, administer sources, retrieve evidence payloads, or replace a SIEM workflow. Missing identity and stale gateway/proxy data are shown as limits rather than proof of bypass.
