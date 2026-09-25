# Configuration reference

Settings use `SHAI_` environment variables, with `.env` supported for local use. Production authentication defaults to JWT and startup fails if issuer, audience, or HTTPS JWKS URL is missing. Do not commit `.env`.

| Setting | Default / purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL DSN; SQLite only in development |
| `TRANSPORT`, `HOST`, `PORT`, `ALLOWED_HOSTS` | Streamable HTTP on loopback:8000; allowlisted Host headers |
| `AUTH_MODE` | `jwt`, `gateway`, or `dev`; default `jwt` |
| `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_JWKS_URL` | Required for JWT; JWKS must be HTTPS |
| `GATEWAY_TRUSTED_CIDRS`, `GATEWAY_IDENTITY_HEADER`, `GATEWAY_SCOPES_HEADER`, `GATEWAY_ASSERTION_HEADER`, `GATEWAY_ASSERTION_SECRET_ENV` | Gateway peer pinning and HMAC assertion configuration |
| `DEVELOPMENT_MODE`, `DEV_TRUSTED_CIDRS` | False by default; stdio and development identity need explicit enablement |
| `CONNECTORS_FILE`, `CATALOG_FILE` | Mounted YAML/JSON config and provider catalog paths |
| `POLLING_SECONDS`, `FRESHNESS_SECONDS`, `CORRELATION_SECONDS` | 300, 900, 120 seconds |
| `MAXIMUM_RESULT_LIMIT`, `MAXIMUM_RANGE_HOURS` | 100 rows, 31 days |
| `MAXIMUM_CONCURRENT_REQUESTS`, `REQUEST_TIMEOUT_SECONDS` | 20 requests, 30 seconds |
| `OBSERVATION_RETENTION_DAYS`, `FINDING_RETENTION_DAYS` | 90 and 365 days |
| `PSEUDONYMIZATION_KEY_ENV` | Name of HMAC key environment variable, unset by default |
| `METADATA_ALLOWLIST` | Empty list; permitted scalar source/registry metadata names |
| `SHARED_EGRESS_IPS`, `ALLOWED_ROUTE_EXCEPTIONS` | Known NAT IPs and explicit MCP server IDs/URLs |
| `RUN_WORKER`, `LOG_LEVEL` | Poller enabled, `INFO` |
| `UI_ENABLED` | False by default; serves the read-only UI at `/ui/` when explicitly enabled |

Connector entries support `connector_id`, `source_type`, `kind`, `endpoint`, `fixture_path`/`file_path`, `secret_env` or `secret_file`, `method`, `static_params`, `field_mapping`, `records_field`, `cursor_field`, parameter names, `mapping_version`, `health_path`, `timeout_seconds`, `retries`, `rate_limit_per_second`, and `max_pages`. See [fixtures](../examples/connectors.yaml) and the [generic HTTP example](../examples/http-connectors.yaml). HTTP connectors require HTTPS outside development. Use a secret manager to mount a secret file or inject a short-lived environment value; no secret goes in YAML.

Catalog entries have `name`, `domains`, `api_domains`, `web_domains`, `regional_domains`, and `required_route`. The shipped catalog uses `.test` domains only. Add verified enterprise destinations before expecting useful recognition. Domain-only evidence is suggestive and reduces to low confidence without actor or device correlation.
