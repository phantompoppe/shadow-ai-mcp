from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from shadow_ai_mcp.connectors.adapters import QueryConnector
from shadow_ai_mcp.connectors.base import ConnectorConfig
from shadow_ai_mcp.workers.runner import Worker


def connector(handler: httpx.MockTransport) -> QueryConnector:
    config = ConnectorConfig(
        connector_id="test-http",
        source_type="siem",
        kind="http",
        endpoint="https://siem.example.test/search",
        retries=1,
        rate_limit_per_second=100,
        field_mapping={
            "source_event_id": "id",
            "observed_at": "timestamp",
            "event_type": "type",
            "destination_url": "destination",
        },
    )
    instance = QueryConnector(config, [], [], None)
    instance._client = httpx.AsyncClient(transport=handler)
    return instance


def event(identity: str) -> dict[str, str]:
    return {
        "id": identity,
        "timestamp": datetime.now(UTC).isoformat(),
        "type": "network_request",
        "destination": "https://example.test/v1",
    }


@pytest.mark.asyncio
async def test_success_pagination_duplicate_and_cursor_recovery() -> None:
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("cursor"))
        if request.url.params.get("cursor") == "page-two":
            return httpx.Response(200, json={"records": [event("same"), event("two")]})
        return httpx.Response(200, json={"records": [event("same")], "next_cursor": "page-two"})

    c = connector(httpx.MockTransport(handle))
    now = datetime.now(UTC)
    assert (await c.test_connection()).status == "healthy"
    one = await c.fetch_observations(now - timedelta(hours=1), now)
    two = await c.fetch_observations(now - timedelta(hours=1), now, one.next_cursor)
    assert one.next_cursor == "page-two"
    assert one.observations[0].observation_id == two.observations[0].observation_id
    assert len({o.observation_id for o in one.observations + two.observations}) == 2
    assert seen[-1] == "page-two"
    await c.close()


@pytest.mark.asyncio
async def test_authentication_failure_timeout_and_rate_limit() -> None:
    now = datetime.now(UTC)
    denied = connector(httpx.MockTransport(lambda _: httpx.Response(401)))
    assert (await denied.test_connection()).error_code == "AUTH_FAILED"
    with pytest.raises(httpx.HTTPStatusError):
        await denied.fetch_observations(now - timedelta(minutes=1), now)
    await denied.close()

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    slow = connector(httpx.MockTransport(timeout))
    assert (await slow.test_connection()).error_code == "CONNECTOR_TIMEOUT"
    await slow.close()

    calls = 0

    def rate(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return (
            httpx.Response(429)
            if calls == 1
            else httpx.Response(200, json={"records": [event("ok")]})
        )

    limited = connector(httpx.MockTransport(rate))
    batch = await limited.fetch_observations(now - timedelta(minutes=1), now)
    assert calls == 2 and len(batch.observations) == 1
    await limited.close()


@pytest.mark.asyncio
async def test_malformed_and_partial_batch() -> None:
    valid = event("ok")
    transport = httpx.MockTransport(
        lambda _: httpx.Response(
            200, json={"records": [valid, {"id": "bad", "type": "network_request"}, "invalid"]}
        )
    )
    c = connector(transport)
    now = datetime.now(UTC)
    batch = await c.fetch_observations(now - timedelta(minutes=1), now)
    assert batch.source_count == 3 and len(batch.observations) == 1
    assert len(batch.errors) == 2
    await c.close()


@pytest.mark.asyncio
async def test_fixture_stale_telemetry_is_reported(
    environment: tuple[object, object, object, object],
) -> None:
    _, _, worker, service = environment
    await worker.cycle()
    freshness, _ = service.repository.freshness(0)
    assert all(value["stale"] for value in freshness.values())


@pytest.mark.asyncio
async def test_partial_batch_keeps_checkpoint_and_recovers(
    environment: tuple[object, object, object, object],
) -> None:
    settings, _, _, service = environment
    broken = True

    def handle(request: httpx.Request) -> httpx.Response:
        records = [event("stable")]
        if broken:
            records.append({"id": "malformed", "type": "network_request"})
        return httpx.Response(200, json={"records": records})

    adapter = connector(httpx.MockTransport(handle))
    partial = Worker(service.repository, [adapter], settings)
    assert await partial.sync(adapter) == 1
    assert service.repository.sync_state("test-http") is None
    assert service.repository.freshness(900)[0]["test-http"]["error_code"] == "PARTIAL_BATCH"
    broken = False
    assert await partial.sync(adapter) == 0  # Replay was deduplicated.
    assert service.repository.sync_state("test-http").checkpoint_time is not None
    await adapter.close()


@pytest.mark.asyncio
async def test_http_registry_adapter() -> None:
    config = ConnectorConfig(
        connector_id="reg",
        source_type="registry",
        kind="http",
        endpoint="https://registry.example.test/assets",
    )
    data = {
        "asset_id": "mcp-1",
        "asset_type": "mcp_server",
        "name": "Test MCP",
        "canonical_endpoint": "https://mcp.example.test/mcp?token=private",
        "metadata": {"prompt": "private", "environment": "production"},
    }
    adapter = QueryConnector(config, [], ["environment"], None)
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"records": [data]}))
    )
    now = datetime.now(UTC)
    batch = await adapter.fetch_observations(now - timedelta(hours=1), now)
    assert batch.assets[0].canonical_endpoint == "https://mcp.example.test/mcp"
    assert batch.assets[0].metadata == {"environment": "production"}
    await adapter.close()
