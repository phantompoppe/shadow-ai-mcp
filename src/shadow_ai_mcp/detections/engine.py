from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from shadow_ai_mcp.models.schemas import Confidence, Finding, Observation, RegistryAsset, Severity
from shadow_ai_mcp.registry.matching import Match, match_assets

DETECTION_VERSION = "1"
TITLES = {
    "SHAI-001": "Possible LLM proxy bypass",
    "SHAI-002": "Required AI route not observed",
    "SHAI-003": "Possible MCP gateway bypass",
    "SHAI-004": "Unapproved MCP server activity",
    "SHAI-005": "Activity after approval expiration",
}
STEPS = [
    "Verify the source event in its system using the evidence reference.",
    "Check gateway/proxy logs, identity mapping, and any approved exception.",
    "Confirm asset owner and approval state before taking action.",
]


def confidence_score(
    observation: Observation,
    *,
    exact_match: bool,
    available: bool,
    registry_fresh: bool,
    shared_egress: bool,
    match_count: int = 0,
) -> tuple[Confidence, list[str]]:
    score = 0.35
    reasons = []
    if observation.user_id or observation.service_account_id:
        score += 0.18
        reasons.append("IDENTITY_CORRELATED")
    if observation.device_id:
        score += 0.15
        reasons.append("DEVICE_CORRELATED")
    if observation.correlation_id:
        score += 0.12
        reasons.append("CORRELATION_ID_PRESENT")
    if exact_match:
        score += 0.1
        reasons.append("EXACT_REGISTRY_MATCH")
    if available:
        score += 0.1
        reasons.append("ROUTE_TELEMETRY_AVAILABLE")
    else:
        score -= 0.2
        reasons.append("ROUTE_TELEMETRY_MISSING_OR_STALE")
    if not registry_fresh:
        score -= 0.2
        reasons.append("REGISTRY_STALE")
    if shared_egress:
        score -= 0.15
        reasons.append("SHARED_EGRESS")
    if match_count:
        score += min(match_count, 2) * 0.04
        reasons.append("INDEPENDENT_SOURCE_CORRELATION")
    if not observation.user_id and not observation.device_id and not observation.service_account_id:
        score = min(score, 0.48)
        reasons.append("IDENTITY_AND_DEVICE_UNAVAILABLE")
    if not available or not registry_fresh:
        score = min(score, 0.69)
    return (
        Confidence.high if score >= 0.78 else Confidence.medium if score >= 0.52 else Confidence.low
    ), reasons


def severity_score(detection_id: str, asset: RegistryAsset | None) -> Severity:
    if detection_id == "SHAI-004":
        return Severity.high if asset and asset.risk_tier == "critical" else Severity.medium
    if detection_id == "SHAI-005":
        return (
            Severity.high if asset and asset.risk_tier in {"high", "critical"} else Severity.medium
        )
    if asset and asset.risk_tier == "critical":
        return Severity.critical
    return Severity.high if asset and asset.risk_tier == "high" else Severity.medium


def correlated(
    a: Observation, b: Observation, window_seconds: int, shared_egress_ips: list[str]
) -> bool:
    if abs((a.observed_at - b.observed_at).total_seconds()) > window_seconds:
        return False
    if a.correlation_id and a.correlation_id == b.correlation_id:
        return True
    identity = bool(
        (a.user_id and a.user_id == b.user_id)
        or (a.service_account_id and a.service_account_id == b.service_account_id)
    )
    device = bool(a.device_id and a.device_id == b.device_id)
    ip = bool(a.source_ip and a.source_ip == b.source_ip and a.source_ip not in shared_egress_ips)
    target = bool(
        (a.provider and a.provider == b.provider)
        or (a.destination_domain and a.destination_domain == b.destination_domain)
        or (a.mcp_server_id and a.mcp_server_id == b.mcp_server_id)
        or (a.mcp_server_url and a.mcp_server_url == b.mcp_server_url)
    )
    return target and (identity or device or ip)


def make_finding(
    detection_id: str,
    obs: Observation,
    asset: RegistryAsset | None,
    confidence: Confidence,
    reasons: list[str],
    *,
    observed: str,
    expected: str,
    limitations: list[str],
) -> Finding:
    finding_id = hashlib.sha256(f"{detection_id}|{obs.observation_id}".encode()).hexdigest()
    fact = f"{obs.event_type} observed at {obs.observed_at.isoformat()} from {obs.source_type}"
    explanation = (
        f"Observed: {fact}. Expected route: {expected}. Observed route: {observed}. "
        f"Reason codes: {', '.join(reasons)}. "
        f"Limitations: {', '.join(limitations) if limitations else 'none noted'}. "
        "This is a deterministic inference and requires human verification."
    )
    return Finding(
        finding_id=finding_id,
        detection_id=detection_id,
        title=TITLES[detection_id],
        summary=(
            f"{TITLES[detection_id]} for "
            f"{obs.destination_domain or obs.mcp_server_id or 'unknown destination'}"
        ),
        severity=severity_score(detection_id, asset),
        confidence=confidence,
        first_seen=obs.observed_at,
        last_seen=obs.observed_at,
        user_id=obs.user_id or obs.service_account_id,
        device_id=obs.device_id,
        application_id=obs.application_id,
        asset_id=asset.asset_id if asset else None,
        provider=obs.provider,
        destination=obs.destination_domain or obs.mcp_server_url,
        mcp_server_id=obs.mcp_server_id,
        required_route=expected,
        observed_route=observed,
        approval_status=asset.approval_status if asset else "unknown",
        evidence_references=[obs.evidence_reference] if obs.evidence_reference else [],
        reason_codes=reasons,
        explanation=explanation,
        recommended_investigation_steps=STEPS,
        detection_version=DETECTION_VERSION,
    )


def detect(
    observations: list[Observation],
    assets: list[RegistryAsset],
    freshness: dict[str, Any],
    *,
    window_seconds: int,
    shared_egress_ips: list[str],
    allowed_exceptions: list[str],
    now: datetime | None = None,
) -> list[tuple[Finding, Observation]]:
    now = now or datetime.now(UTC)
    proxies = [
        o
        for o in observations
        if o.source_type == "llm_proxy" and o.route_status in {"success", "allowed"}
    ]
    gateways = [
        o
        for o in observations
        if o.source_type == "mcp_gateway" and o.route_status in {"success", "allowed"}
    ]

    def available(kind: str) -> bool:
        return any(
            s.get("source_type") == kind and s.get("health") == "healthy" and not s.get("stale")
            for s in freshness.values()
        )

    registry_fresh = available("registry")
    results: list[tuple[Finding, Observation]] = []
    for obs in observations:
        direct = obs.source_type == "siem" and obs.route_type not in {"llm_proxy", "mcp_gateway"}
        mcp = obs.event_type == "mcp_connection" or bool(obs.mcp_server_id or obs.mcp_server_url)
        candidates = match_assets(
            assets,
            server_id=obs.mcp_server_id if mcp else None,
            endpoint=obs.mcp_server_url if mcp else obs.destination_url,
            domain=obs.destination_domain if not mcp else None,
            asset_type="mcp_server" if mcp else None,
        )
        matched: Match | None = candidates[0] if candidates else None
        asset = matched.asset if matched else None
        exact = matched is not None and matched.method != "domain_alias"
        route_available = available("mcp_gateway" if mcp else "llm_proxy")
        shared = bool(obs.source_ip and obs.source_ip in shared_egress_ips)
        conf, common = confidence_score(
            obs,
            exact_match=exact,
            available=route_available,
            registry_fresh=registry_fresh,
            shared_egress=shared,
        )
        limits = []
        if not route_available:
            limits.append("approved route telemetry is missing or stale")
        if not registry_fresh:
            limits.append("registry data is missing or stale")
        if shared:
            limits.append("source IP is shared egress")
        if not (obs.user_id or obs.device_id or obs.service_account_id):
            limits.append("user and device identity are unavailable")
        if mcp:
            bypass_exception = (
                obs.source_ip in {"127.0.0.1", "::1"}
                or obs.metadata.get("environment") in {"test", "development", "local"}
                or obs.mcp_server_id in allowed_exceptions
                or obs.mcp_server_url in allowed_exceptions
            )
            route_required = not asset or asset.required_route != "none"
            if (
                direct
                and route_required
                and not bypass_exception
                and not any(
                    correlated(obs, gate, window_seconds, shared_egress_ips) for gate in gateways
                )
            ):
                results.append(
                    (
                        make_finding(
                            "SHAI-003",
                            obs,
                            asset,
                            conf,
                            common + ["GATEWAY_EVENT_NOT_CORRELATED"],
                            observed=obs.route_type or "direct",
                            expected="mcp_gateway",
                            limitations=limits,
                        ),
                        obs,
                    )
                )
            if not asset or asset.approval_status != "approved":
                registry_conf = conf if registry_fresh else Confidence.low
                results.append(
                    (
                        make_finding(
                            "SHAI-004",
                            obs,
                            asset,
                            registry_conf,
                            common + ["NO_ACTIVE_REGISTRY_MATCH"],
                            observed=obs.route_type or "direct",
                            expected="approved registry entry",
                            limitations=limits,
                        ),
                        obs,
                    )
                )
        elif direct:
            recognized = bool(obs.provider or asset)
            if recognized and not any(
                correlated(obs, proxy, window_seconds, shared_egress_ips) for proxy in proxies
            ):
                results.append(
                    (
                        make_finding(
                            "SHAI-001",
                            obs,
                            asset,
                            conf,
                            common + ["PROXY_EVENT_NOT_CORRELATED"],
                            observed="direct",
                            expected="llm_proxy",
                            limitations=limits,
                        ),
                        obs,
                    )
                )
                if asset and asset.required_route == "llm_proxy":
                    results.append(
                        (
                            make_finding(
                                "SHAI-002",
                                obs,
                                asset,
                                conf,
                                common + ["REGISTRY_REQUIRES_PROXY"],
                                observed="direct",
                                expected="llm_proxy",
                                limitations=limits,
                            ),
                            obs,
                        )
                    )
        if asset and asset.expiration_date and asset.expiration_date < obs.observed_at:
            expiry_conf = conf if registry_fresh else Confidence.low
            results.append(
                (
                    make_finding(
                        "SHAI-005",
                        obs,
                        asset,
                        expiry_conf,
                        common + ["APPROVAL_EXPIRED"],
                        observed=obs.route_type or "direct",
                        expected=asset.required_route,
                        limitations=limits,
                    ),
                    obs,
                )
            )
    return results
