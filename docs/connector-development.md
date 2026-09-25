# Connector development guide

Add a source without changing detections or MCP tools:

1. Define a `ConnectorConfig` entry with stable `connector_id`, `source_type`, endpoint or file path, field mapping, timeout, retry limit, pagination fields, and a read-only secret reference.
2. For a common HTTP JSON query API, use `QueryConnector` directly. It sends start/end UTC timestamps, cursor, and page limit as configured GET query parameters or POST JSON query fields. It never sends prompts or connector credentials to storage.
3. For a vendor API, subclass `QueryConnector` or implement the typed `Connector` protocol in `connectors/base.py`, then register the class in `ADAPTERS`. Return `ObservationBatch` with normalized `Observation` or validated `RegistryAsset` objects, `next_cursor`, and sanitized error codes.
4. Add contract tests for health, 401/403, timeout, 429 retry, malformed records, partial batches, replayed events, cursor recovery, and stale telemetry. Use a fake HTTP transport. Do not place live credentials in fixtures.
5. Configure the connector; the worker, detector, storage, and six tools use the common schema without source-specific branches.

The source adapter owns pagination and checkpoint semantics. The worker persists each page before advancing the cursor. A partial batch keeps the old checkpoint; fix the mapping or source event, then sync again. An operator can reset a connector checkpoint in the database during a maintenance window, but there is no admin MCP tool.

Field mappings are `normalized_field: source_field`. Mappings to or from prompt, response, body, tool arguments/results, authorization, cookies, tokens, API keys, or credentials are rejected. Omit raw fields. `metadata_allowlist` is empty by default; permitted scalar values are truncated and redacted. Evidence references must be stable, query-free source-system URIs without userinfo. Use a least-privilege API credential that permits query only. Registry records use the schema in [data model](data-model.md).
