# Troubleshooting

| Symptom | Check |
| --- | --- |
| Startup rejects authentication | Set issuer, audience, HTTPS JWKS for JWT, or signed gateway CIDR/secret. Dev mode needs explicit enablement. |
| HTTP 421 | Set `SHAI_ALLOWED_HOSTS` to the actual Host header, including the port used by the client. |
| HTTP 401 or 403 | Inspect gateway peer IP, HMAC timestamp/signature, token claims, and `shadow_ai:read` scope. |
| `/readyz` is 503 | Check PostgreSQL connection, migration version, and credentials. |
| Findings have low confidence | Inspect connector `last_success`, registry freshness, user/device mapping, and NAT/shared egress settings. |
| No findings | Check fixture/source record mapping, provider catalog, registry aliases, connector status, route status, and correlation window. Healthy approved events should remain clear. |
| `PARTIAL_BATCH` | Inspect rejected record counts, fix mapping/source shape, and replay; the prior checkpoint is kept. No rejected payload is logged. |
| Cursor repeats or pagination stops | Confirm the source API advances `next_cursor` and honors `limit`; the worker bounds maximum pages. |
| SDK connection times out | Confirm Streamable HTTP `/mcp`, private network reachability, Host allowlist, TLS proxy, and runtime startup. |

The MCP tools expose freshness and structured errors, while `connectors` and `connector_sync_state` record sanitized status. Do not paste raw connector responses or credentials into issue reports. Use source evidence references through the source system's authorized workflow.
