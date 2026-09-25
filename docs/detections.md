# Detection catalog

All rules use detection version `1`, deterministic inputs, and separate confidence and severity calculations. Findings are investigative leads, not confirmed violations. Sources of increased confidence include actor, device, correlation ID, exact registry endpoint, and healthy route telemetry. Missing identity, stale proxy/gateway/registry, and shared egress reduce confidence. Risk tier influences severity but never confidence.

| ID | Condition | Caveat |
| --- | --- | --- |
| SHAI-001 | Recognized direct AI destination has no correlated successful proxy request within the window | Missing route logs, NAT, and delayed delivery lower confidence |
| SHAI-002 | Same direct activity matches registry policy requiring `llm_proxy` | Distinct policy reason; may coexist with SHAI-001 |
| SHAI-003 | Direct MCP client/server activity lacks correlated successful gateway event | Local/test and configured exceptions skip bypass rule; `required_route=none` permits direct |
| SHAI-004 | MCP activity has no approved registry match by ID, exact URL, alternate URL, or domain alias | Registry outage/staleness makes it low confidence |
| SHAI-005 | AI or MCP activity occurs after matched approval expiration | Cached stale registry makes it low confidence |

The sample correlation window is 120 seconds. A correlation ID match is strongest; otherwise target and actor, device, or nonshared IP must align. No user/device identity caps confidence below medium. One source's absence is negative evidence only when its connector reports healthy recent synchronization. The false-positive checklist is returned by `explain_shadow_ai_finding`.
