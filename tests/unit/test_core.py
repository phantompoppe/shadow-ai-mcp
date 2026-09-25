from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from shadow_ai_mcp.auth.core import Principal, SecurityError, current_principal, require
from shadow_ai_mcp.detections.engine import confidence_score, detect, severity_score
from shadow_ai_mcp.models.schemas import (
    ApprovalInput,
    Confidence,
    Observation,
    RangeInput,
    RegistryAsset,
    SearchInput,
    Severity,
)
from shadow_ai_mcp.normalization.core import normalize_observation, normalize_url, safe_text
from shadow_ai_mcp.registry.matching import match_assets
from shadow_ai_mcp.storage.db import Base, Database
from shadow_ai_mcp.storage.repository import Repository, cursor_decode

NOW = datetime.now(UTC) - timedelta(minutes=5)


def obs(**values: object) -> Observation:
    data = dict(
        observation_id="event",
        connector_id="siem",
        source_type="siem",
        event_type="network_request",
        observed_at=NOW,
        destination_url="https://api.example.test/v1",
        destination_domain="api.example.test",
        provider="example",
        route_type="direct",
        evidence_reference="siem://event/1",
    )
    data.update(values)
    return Observation.model_validate(data)


def asset(**values: object) -> RegistryAsset:
    data = dict(
        asset_id="ai-1",
        asset_type="ai_service",
        name="Example",
        canonical_endpoint="https://api.example.test/v1",
        required_route="llm_proxy",
        approval_status="approved",
        expiration_date=NOW + timedelta(days=1),
    )
    data.update(values)
    return RegistryAsset.model_validate(data)


def healthy() -> dict[str, dict[str, object]]:
    return {
        name: {"source_type": kind, "health": "healthy", "stale": False}
        for name, kind in [
            ("siem", "siem"),
            ("proxy", "llm_proxy"),
            ("gateway", "mcp_gateway"),
            ("registry", "registry"),
        ]
    }


def rules(
    events: list[Observation],
    assets: list[RegistryAsset],
    freshness: dict[str, dict[str, object]] | None = None,
) -> list[object]:
    return [
        finding
        for finding, _ in detect(
            events,
            assets,
            freshness or healthy(),
            window_seconds=120,
            shared_egress_ips=[],
            allowed_exceptions=[],
        )
    ]


def test_url_domain_and_redaction() -> None:
    assert normalize_url("HTTPS://API.Example.TEST:443/Case/Path/?prompt=private&x=1") == (
        "https://api.example.test/Case/Path/"
    )
    assert normalize_url("example.test/Other") == "https://example.test/Other"
    assert safe_text("Bearer this-is-secret") == "[REDACTED]"
    with pytest.raises(ValueError):
        normalize_url("file:///etc/passwd")


def test_normalization_dedup_and_payload_exclusion(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = {
        "id": "event-1",
        "time": NOW.isoformat(),
        "event": "network_request",
        "destination": "https://API.example.test/v1?prompt=NEVER_STORE",
        "user": "Alice",
        "prompt": "NEVER_STORE",
        "api_key": "NEVER_STORE",
        "environment": "production",
        "evidence": "siem://events/1",
    }
    mapping = {
        "source_event_id": "id",
        "observed_at": "time",
        "event_type": "event",
        "destination_url": "destination",
        "user_id": "user",
        "evidence_reference": "evidence",
    }
    one = normalize_observation(
        raw,
        connector_id="siem",
        source_type="siem",
        mapping=mapping,
        mapping_version="1",
        metadata_allowlist=["environment", "api_key"],
        catalog=[],
        pseudonymization_key_env=None,
    )
    two = normalize_observation(
        raw,
        connector_id="siem",
        source_type="siem",
        mapping=mapping,
        mapping_version="1",
        metadata_allowlist=["environment"],
        catalog=[],
        pseudonymization_key_env=None,
    )
    assert one.observation_id == two.observation_id
    assert one.destination_domain == "api.example.test"
    assert "NEVER_STORE" not in one.model_dump_json()
    assert one.evidence_hash and one.metadata == {"environment": "production"}
    monkeypatch.setenv("PSEUDONYM_KEY", "development-test-key")
    hashed = normalize_observation(
        raw,
        connector_id="siem",
        source_type="siem",
        mapping=mapping,
        mapping_version="1",
        metadata_allowlist=[],
        catalog=[],
        pseudonymization_key_env="PSEUDONYM_KEY",
    )
    assert hashed.user_id != "Alice"
    with pytest.raises(ValueError, match="prohibited"):
        normalize_observation(
            raw,
            connector_id="siem",
            source_type="siem",
            mapping={"model": "prompt"},
            mapping_version="1",
            metadata_allowlist=[],
            catalog=[],
        )


def test_registry_matching() -> None:
    entry = asset(alternate_endpoints=["https://alias.example.test/MCP"])
    assert match_assets([entry], endpoint="https://API.example.test:443/v1")[0].method == (
        "canonical_endpoint"
    )
    assert match_assets([entry], endpoint="https://alias.example.test/MCP")[0].method == (
        "alternate_endpoint"
    )
    assert match_assets([entry], domain="alias.example.test")[0].method == "domain_alias"
    assert match_assets([entry], asset_id="ai-1")[0].method == "asset_id"


def test_all_rules_and_approved_correlation() -> None:
    approved = obs(observation_id="approved", user_id="alice", correlation_id="same")
    proxy = obs(
        observation_id="proxy",
        source_type="llm_proxy",
        route_type="llm_proxy",
        route_status="success",
        user_id="alice",
        correlation_id="same",
    )
    assert rules([approved, proxy], [asset()]) == []
    direct = obs(observation_id="direct", user_id="bob", device_id="device-b")
    ids = {f.detection_id for f in rules([direct], [asset()])}
    assert ids == {"SHAI-001", "SHAI-002"}
    mcp = obs(
        observation_id="mcp",
        event_type="mcp_connection",
        provider=None,
        mcp_server_id="rogue",
        mcp_server_url="https://rogue.example.test/mcp",
        user_id="bob",
        device_id="device-b",
    )
    assert {f.detection_id for f in rules([mcp], [])} == {"SHAI-003", "SHAI-004"}
    expired = asset(expiration_date=NOW - timedelta(days=1))
    assert "SHAI-005" in {f.detection_id for f in rules([direct], [expired])}
    assert "SHAI-005" in {f.detection_id for f in rules([proxy], [expired])}


def test_mcp_exceptions_and_gateway_correlation() -> None:
    direct = obs(
        observation_id="mcp",
        event_type="mcp_connection",
        provider=None,
        mcp_server_id="mcp-1",
        mcp_server_url="https://mcp.example.test/mcp",
        user_id="u",
        correlation_id="request-1",
    )
    gateway = obs(
        observation_id="gateway",
        source_type="mcp_gateway",
        event_type="mcp_request",
        route_type="mcp_gateway",
        route_status="success",
        mcp_server_id="mcp-1",
        mcp_server_url="https://mcp.example.test/mcp",
        correlation_id="request-1",
    )
    registered = asset(
        asset_id="mcp-1",
        asset_type="mcp_server",
        canonical_endpoint="https://mcp.example.test/mcp",
        required_route="mcp_gateway",
    )
    assert rules([direct, gateway], [registered]) == []
    assert rules([direct], [registered])[0].detection_id == "SHAI-003"
    assert rules([direct.model_copy(update={"source_ip": "127.0.0.1"})], [registered]) == []
    registered.required_route = "none"
    assert rules([direct], [registered]) == []


def test_confidence_and_severity_independent() -> None:
    strong = obs(user_id="bob", device_id="laptop", correlation_id="corr")
    high, reasons = confidence_score(
        strong, exact_match=True, available=True, registry_fresh=True, shared_egress=False
    )
    low, low_reasons = confidence_score(
        obs(user_id=None, device_id=None),
        exact_match=False,
        available=False,
        registry_fresh=False,
        shared_egress=True,
    )
    assert high == Confidence.high and low == Confidence.low
    assert "ROUTE_TELEMETRY_MISSING_OR_STALE" in low_reasons
    assert "EXACT_REGISTRY_MATCH" in reasons
    assert severity_score("SHAI-001", asset(risk_tier="critical")) == Severity.critical
    assert severity_score("SHAI-004", None) == Severity.medium


def test_missing_registry_or_gateway_lowers_confidence() -> None:
    mcp = obs(
        observation_id="mcp-gap",
        event_type="mcp_connection",
        provider=None,
        mcp_server_id="unknown",
        mcp_server_url="https://unknown.example.test/mcp",
        user_id="bob",
        device_id="device-b",
    )
    gap = {"siem": healthy()["siem"]}
    findings = rules([mcp], [], gap)
    assert {f.detection_id for f in findings} == {"SHAI-003", "SHAI-004"}
    assert all(f.confidence != Confidence.high for f in findings)
    assert any("REGISTRY_STALE" in f.reason_codes for f in findings)


def test_pagination_validation_and_authorization(tmp_path: object) -> None:
    db = Database("sqlite:///:memory:")
    Base.metadata.create_all(db.engine)
    repo = Repository(db)
    event = obs(user_id="bob")
    repo.save_observations([event])
    findings = rules([event], [asset()])
    repo.save_findings([(finding, event) for finding in findings])
    first, cursor = repo.search(SearchInput(limit=1))
    second, _ = repo.search(SearchInput(limit=1, cursor=cursor))
    assert len(first) == len(second) == 1 and first[0].finding_id != second[0].finding_id
    with pytest.raises(ValueError, match="cursor"):
        cursor_decode("not-a-valid-cursor")
    with pytest.raises(ValidationError):
        ApprovalInput()
    with pytest.raises(ValidationError):
        RangeInput(start_time=NOW, end_time=NOW - timedelta(seconds=1))
    with pytest.raises(ValidationError):
        SearchInput(limit=501)
    with pytest.raises(SecurityError):
        require("shadow_ai:read")
    token = current_principal.set(Principal("tester", frozenset({"shadow_ai:read"})))
    try:
        require("shadow_ai:read")
        with pytest.raises(SecurityError):
            require("shadow_ai:evidence:read")
    finally:
        current_principal.reset(token)
