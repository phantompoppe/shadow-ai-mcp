from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from mcp.client import Client
from sqlalchemy import select

from shadow_ai_mcp.auth.core import Principal, current_principal
from shadow_ai_mcp.storage.db import AuditRow, ObservationRow


@pytest.mark.asyncio
async def test_demo_service_six_tools_and_privacy(
    environment: tuple[object, object, object, object],
) -> None:
    _, mcp, worker, service = environment
    await worker.cycle()
    principal = current_principal.set(
        Principal("security-analyst", frozenset({"shadow_ai:read", "shadow_ai:evidence:read"}))
    )
    try:
        async with Client(mcp) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert names == {
                "search_shadow_ai",
                "get_shadow_ai_finding",
                "explain_shadow_ai_finding",
                "find_llm_proxy_bypass",
                "find_mcp_gateway_bypass",
                "check_ai_approval",
            }

            async def invoke(name: str, args: dict[str, object]) -> dict[str, object]:
                result = await client.call_tool(name, args)
                assert not result.is_error
                data = result.structured_content
                assert isinstance(data, dict) and data.get("error") is None
                return data

            search = await invoke("search_shadow_ai", {"limit": 50})
            findings = search["findings"]
            assert isinstance(findings, list)
            detections = {f["detection_id"] for f in findings}
            assert detections == {f"SHAI-00{n}" for n in range(1, 6)}
            assert not any(
                "net-approved" in json.dumps(f) or "net-mcp-approved" in json.dumps(f)
                for f in findings
            )
            assert all(f["evidence_references"] for f in findings)
            assert any(f["confidence"] == "low" and f["user_id"] is None for f in findings)
            assert not search["warnings"]
            expired = next(f for f in findings if f["detection_id"] == "SHAI-005")
            detail = await invoke("get_shadow_ai_finding", {"finding_id": expired["finding_id"]})
            assert detail["asset"]["asset_id"] == "ai-expired"
            explanation = await invoke(
                "explain_shadow_ai_finding", {"finding_id": expired["finding_id"]}
            )
            assert explanation["details"]["recommended_steps"]
            start = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
            end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
            ai = await invoke(
                "find_llm_proxy_bypass",
                {"start_time": start, "end_time": end, "minimum_confidence": "low"},
            )
            assert {f["detection_id"] for f in ai["findings"]} <= {"SHAI-001", "SHAI-002"}
            mcp_result = await invoke(
                "find_mcp_gateway_bypass",
                {"start_time": start, "end_time": end, "minimum_confidence": "low"},
            )
            assert {"SHAI-003", "SHAI-004"} <= {f["detection_id"] for f in mcp_result["findings"]}
            approval = await invoke("check_ai_approval", {"asset_id": "ai-expired"})
            assert approval["details"]["expired"] is True
            assert approval["details"]["required_route"] == "llm_proxy"
            assert "NEVER INGEST THIS" not in json.dumps(
                [search, detail, explanation, ai, mcp_result, approval]
            )
    finally:
        current_principal.reset(principal)
    limited = current_principal.set(Principal("reader", frozenset({"shadow_ai:read"})))
    try:
        redacted = service.get(expired["finding_id"])
        assert redacted.finding and all(
            ref.startswith("sha256:") for ref in redacted.finding.evidence_references
        )
    finally:
        current_principal.reset(limited)
    with service.repository.db.session() as session:
        assert len(session.scalars(select(AuditRow)).all()) == 6
        serialized = json.dumps([row.data for row in session.scalars(select(ObservationRow)).all()])
    assert "NEVER INGEST THIS" not in serialized
