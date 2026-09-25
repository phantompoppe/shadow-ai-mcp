# MCP tool reference

All six tools require `shadow_ai:read`. A caller with `shadow_ai:evidence:read` additionally sees source reference URIs; otherwise the same field contains SHA-256 reference hashes. No tool retrieves raw source records or modifies state. Each result has `observed_facts`, `inferred_conclusions`, `telemetry_freshness`, `warnings`, and a structured `error` when applicable. Timestamps are UTC ISO 8601. List results use a stable opaque cursor and enforce the configured maximum limit.

| Tool | Required arguments | Result |
| --- | --- | --- |
| `search_shadow_ai` | Optional finding filters, `limit`, `cursor` | Findings, active filters, next cursor |
| `get_shadow_ai_finding` | `finding_id` | Full finding and related asset |
| `explain_shadow_ai_finding` | `finding_id` | Observed, expected, missing evidence, confidence, false positives, human steps |
| `find_llm_proxy_bypass` | `start_time`, `end_time`; optional actor/device/provider, confidence, page | SHAI-001/002 |
| `find_mcp_gateway_bypass` | `start_time`, `end_time`; optional actor/server, confidence, page | SHAI-003/004 |
| `check_ai_approval` | At least one of `asset_id`, `name`, `endpoint`; optional `asset_type` | Registry matches, approval, expiry, route, owner, match method, ambiguity |

Stable application error categories include `INVALID_REQUEST`, `UNAUTHENTICATED`, `FORBIDDEN`, `NOT_FOUND`, `CONNECTOR_UNAVAILABLE`, `TELEMETRY_STALE`, `QUERY_RANGE_TOO_LARGE`, `RATE_LIMITED`, and `INTERNAL_ERROR`. Authentication can reject at HTTP 401 before MCP dispatch; schema errors from the MCP SDK may be returned as protocol validation errors before an application tool starts. Consult health, freshness warnings, and audit records when investigating a failed call.
