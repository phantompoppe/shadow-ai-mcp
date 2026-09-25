from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import select

from shadow_ai_mcp.auth.core import Principal
from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.server.app import RequestGuard, build
from shadow_ai_mcp.server.ui import build_ui
from shadow_ai_mcp.storage.db import AuditRow


@pytest.mark.asyncio
async def test_ui_uses_read_only_service_and_records_audit(
    environment: tuple[Settings, object, object, object],
) -> None:
    settings, _, worker, service = environment
    await worker.cycle()
    settings.ui_enabled = True
    _, app, _, service = build(settings)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
        page = await client.get("/ui/")
        assert page.status_code == 200
        assert "Shadow AI findings" in page.text
        assert "default-src 'none'" in page.headers["content-security-policy"]
        script = await client.get("/ui/app.js")
        assert script.status_code == 200 and "textContent" in script.text
        result = await client.post("/ui/api/findings", json={"limit": 2})
        assert result.status_code == 200
        data = result.json()
        assert len(data["findings"]) == 2 and data["next_cursor"]
        assert data["telemetry_freshness"]
        finding_id = data["findings"][0]["finding_id"]
        detail = await client.get(f"/ui/api/findings/{finding_id}")
        explanation = await client.get(f"/ui/api/findings/{finding_id}/explanation")
        assert detail.status_code == explanation.status_code == 200
        assert detail.json()["finding"]["evidence_references"]
        assert explanation.json()["details"]["recommended_steps"]
        approval = await client.post("/ui/api/approval", json={"asset_id": "ai-expired"})
        assert approval.status_code == 200 and approval.json()["details"]["expired"]
        next_page = await client.post(
            "/ui/api/findings", json={"limit": 2, "cursor": data["next_cursor"]}
        )
        assert next_page.status_code == 200
        assert next_page.json()["findings"][0]["finding_id"] != finding_id
        invalid = await client.post("/ui/api/findings", json={"surprise": "value"})
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == "INVALID_REQUEST"
        secret_url = await client.post(
            "/ui/api/approval", json={"endpoint": "https://ai.test/?token=secret"}
        )
        assert secret_url.status_code == 400
        assert "token=secret" not in json.dumps(secret_url.json())
        remote = httpx.ASGITransport(app=app, client=("10.2.3.4", 1234))
        async with httpx.AsyncClient(
            transport=remote, base_url="http://127.0.0.1:8000"
        ) as outsider:
            assert (await outsider.post("/ui/api/findings", json={})).status_code == 401
    with service.repository.db.session() as session:
        audit = session.scalars(select(AuditRow)).all()
    assert any(row.tool_name == "ui_search_findings" and row.outcome == "success" for row in audit)
    assert any(
        row.tool_name == "ui_check_approval" and row.outcome == "INVALID_REQUEST" for row in audit
    )
    assert "token=secret" not in json.dumps([row.filters for row in audit])


@pytest.mark.asyncio
async def test_ui_requires_read_scope(
    environment: tuple[Settings, object, object, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings, _, worker, service = environment
    guard = RequestGuard(
        build_ui(service, settings), settings, service.repository, required_scope="shadow_ai:read"
    )
    monkeypatch.setattr(
        guard.auth,
        "authenticate",
        lambda headers, peer_ip: Principal("limited", frozenset()),
    )
    transport = httpx.ASGITransport(app=guard, client=("127.0.0.1", 1234))
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        response = await client.post("/api/findings", json={})
    assert response.status_code == 403 and response.json()["code"] == "FORBIDDEN"
    monkeypatch.setattr(
        guard.auth,
        "authenticate",
        lambda headers, peer_ip: Principal("reader", frozenset({"shadow_ai:read"})),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
        before = await client.post("/api/findings", json={})
        assert before.status_code == 200
        assert before.json()["warnings"]
        await worker.cycle()
        after = await client.post("/api/findings", json={"limit": 2})
    assert after.status_code == 200
    assert all(
        reference.startswith("sha256:")
        for finding in after.json()["findings"]
        for reference in finding["evidence_references"]
    )
