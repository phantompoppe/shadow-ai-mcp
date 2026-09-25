from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import inspect, select

from shadow_ai_mcp.auth.core import Authenticator, Principal, SecurityError, current_principal
from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.models.schemas import SearchInput
from shadow_ai_mcp.server.app import RequestGuard, build
from shadow_ai_mcp.storage.db import AuditRow, ConnectorRow, EvidenceRow, ObservationRow


@pytest.mark.asyncio
async def test_fixture_ingestion_persistence_checkpoint_and_update(
    environment: tuple[Settings, object, object, object],
) -> None:
    settings, _, worker, service = environment
    assert worker is not None
    created, updated = await worker.cycle()
    assert created >= 6 and updated == 0
    with service.repository.db.session() as session:
        assert len(session.scalars(select(ObservationRow)).all()) == 8
    _, _, restarted_worker, restarted_service = build(settings)
    created3, updated3 = await restarted_worker.cycle()
    assert created3 == 0 and updated3 >= created
    with restarted_service.repository.db.session() as session:
        assert len(session.scalars(select(ObservationRow)).all()) == 8
        assert len(session.scalars(select(EvidenceRow)).all()) == created
        assert len(session.scalars(select(ConnectorRow)).all()) == 4
    assert service.repository.sync_state("central-siem").checkpoint_time
    created2, updated2 = await worker.cycle()
    assert created2 == 0 and updated2 >= created
    with service.repository.db.session() as session:
        assert len(session.scalars(select(ObservationRow)).all()) == 8
    tables = inspect(service.repository.db.engine).get_table_names()
    assert {
        "connectors",
        "connector_sync_state",
        "observations",
        "registry_assets",
        "findings",
        "finding_evidence",
        "detection_runs",
        "audit_events",
    } <= set(tables)
    database_dump = json.dumps(
        [
            o.data
            for o in service.repository.db.session_factory().scalars(select(ObservationRow)).all()
        ]
    )
    for prohibited in (
        "NEVER INGEST THIS",
        "tool_arguments",
        "tool_result",
        "request_body",
        "api_key",
        "prompt",
    ):
        assert prohibited not in database_dump
    assert settings.development_mode


def test_missing_connector_warnings(environment: tuple[Settings, object, object, object]) -> None:
    _, _, _, service = environment
    freshness, warnings = service.repository.freshness(900)
    assert freshness["missing:mcp_gateway"]["stale"] is True
    assert any("mcp_gateway" in message for message in warnings)


def test_authentication_and_auditing(environment: tuple[Settings, object, object, object]) -> None:
    settings, _, _, service = environment
    with pytest.raises(SecurityError):
        Authenticator(settings).authenticate({}, "10.1.0.1")
    with pytest.raises(ValueError):
        Settings(database_url=settings.database_url, auth_mode="gateway", gateway_trusted_cidrs=[])
    with pytest.raises(ValueError):
        Settings(database_url=settings.database_url, auth_mode="jwt")
    service.execute(
        "search_shadow_ai", {"user_id": "secret-user"}, lambda: service.search(SearchInput())
    )
    token = current_principal.set(Principal("reader", frozenset({"shadow_ai:read"})))
    try:
        service.execute(
            "search_shadow_ai", {"user_id": "secret-user"}, lambda: service.search(SearchInput())
        )
    finally:
        current_principal.reset(token)
    with service.repository.db.session() as session:
        audits = session.scalars(select(AuditRow)).all()
    assert [a.outcome for a in audits] == ["UNAUTHENTICATED", "success"]
    assert "secret-user" not in json.dumps([a.filters for a in audits])


@pytest.mark.asyncio
async def test_http_auth_middleware(environment: tuple[Settings, object, object, object]) -> None:
    settings, _, _, service = environment
    guard = RequestGuard(httpx_app(), settings, service.repository)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=guard, client=("10.1.0.1", 1234)),
        base_url="http://example.test",
    ) as client:
        unauthorized = await client.post("/mcp", json={})
        assert unauthorized.status_code == 401
        assert unauthorized.json()["code"] == "UNAUTHENTICATED"
    with service.repository.db.session() as session:
        audits = session.scalars(select(AuditRow)).all()
    assert len(audits) == 1 and audits[0].outcome == "UNAUTHENTICATED"
    assert service.repository.db.healthy()


def httpx_app() -> object:
    async def app(scope: object, receive: object, send: object) -> None:
        # Authentication test never invokes the wrapped application.
        raise AssertionError("unauthenticated request reached application")

    return app
