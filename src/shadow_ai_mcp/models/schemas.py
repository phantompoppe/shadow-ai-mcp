from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Confidence(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class Severity(StrEnum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Observation(StrictModel):
    observation_id: str
    source_event_id: str | None = None
    source_type: str
    connector_id: str
    event_type: str
    observed_at: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    user_id: str | None = None
    user_email: str | None = None
    service_account_id: str | None = None
    device_id: str | None = None
    source_ip: str | None = None
    application_id: str | None = None
    application_name: str | None = None
    destination_url: str | None = None
    destination_domain: str | None = None
    destination_ip: str | None = None
    provider: str | None = None
    model: str | None = None
    mcp_client: str | None = None
    mcp_server_id: str | None = None
    mcp_server_name: str | None = None
    mcp_server_url: str | None = None
    mcp_tool_name: str | None = None
    mcp_authentication_method: str | None = None
    route_type: str | None = None
    route_status: str | None = None
    correlation_id: str | None = None
    evidence_reference: str | None = None
    evidence_hash: str | None = None
    mapping_version: str = "1"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at", "ingested_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must contain a timezone")
        return value.astimezone(UTC)


class RegistryAsset(StrictModel):
    asset_id: str = Field(max_length=256)
    asset_type: str
    name: str = Field(max_length=256)
    canonical_endpoint: str = Field(max_length=1024)
    alternate_endpoints: list[str] = Field(default_factory=list)
    owner: str | None = None
    business_purpose: str | None = None
    approval_status: str = "approved"
    approval_date: datetime | None = None
    expiration_date: datetime | None = None
    allowed_users: list[str] = Field(default_factory=list)
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_applications: list[str] = Field(default_factory=list)
    allowed_environments: list[str] = Field(default_factory=list)
    required_route: str = "none"
    risk_tier: str = "medium"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("asset_type")
    @classmethod
    def asset_type_valid(cls, value: str) -> str:
        if value not in {"ai_service", "llm_provider", "mcp_server"}:
            raise ValueError("invalid asset type")
        return value

    @field_validator("required_route")
    @classmethod
    def route_valid(cls, value: str) -> str:
        if value not in {"llm_proxy", "mcp_gateway", "none"}:
            raise ValueError("invalid required route")
        return value

    @field_validator("approval_date", "expiration_date")
    @classmethod
    def optional_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("registry dates require a timezone")
        return value.astimezone(UTC) if value else None


class ProviderEntry(StrictModel):
    name: str = Field(max_length=128)
    domains: list[str] = Field(default_factory=list)
    api_domains: list[str] = Field(default_factory=list)
    web_domains: list[str] = Field(default_factory=list)
    regional_domains: list[str] = Field(default_factory=list)
    required_route: Literal["llm_proxy", "mcp_gateway", "none"] = "llm_proxy"

    @field_validator("domains", "api_domains", "web_domains", "regional_domains")
    @classmethod
    def canonical_domains(cls, values: list[str]) -> list[str]:
        if len(values) > 100:
            raise ValueError("too many provider domains")
        result = [value.lower().strip().rstrip(".") for value in values]
        if any(not value or value.startswith("*.") or "/" in value for value in result):
            raise ValueError("invalid provider domain")
        return result


class Finding(StrictModel):
    finding_id: str
    detection_id: str
    title: str
    summary: str
    status: str = "open"
    severity: Severity
    confidence: Confidence
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    user_id: str | None = None
    device_id: str | None = None
    application_id: str | None = None
    asset_id: str | None = None
    provider: str | None = None
    destination: str | None = None
    mcp_server_id: str | None = None
    required_route: str | None = None
    observed_route: str | None = None
    approval_status: str | None = None
    evidence_references: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
    explanation: str
    recommended_investigation_steps: list[str] = Field(default_factory=list)
    detection_version: str = "1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SearchInput(StrictModel):
    detection_ids: list[str] | None = None
    statuses: list[str] | None = None
    severities: list[Severity] | None = None
    confidence_levels: list[Confidence] | None = None
    user_id: str | None = None
    device_id: str | None = None
    provider: str | None = None
    destination: str | None = None
    mcp_server_id: str | None = None
    first_seen_after: datetime | None = None
    last_seen_before: datetime | None = None
    limit: int = Field(default=50, ge=1, le=500)
    cursor: str | None = None

    @field_validator("statuses")
    @classmethod
    def statuses_valid(cls, value: list[str] | None) -> list[str] | None:
        if value and not set(value) <= {"open", "acknowledged", "resolved", "suppressed"}:
            raise ValueError("invalid finding status")
        return value

    @field_validator("first_seen_after", "last_seen_before")
    @classmethod
    def search_utc(cls, value: datetime | None) -> datetime | None:
        if value and value.tzinfo is None:
            raise ValueError("timestamps require an offset")
        return value.astimezone(UTC) if value else None


class RangeInput(StrictModel):
    start_time: datetime
    end_time: datetime
    user_id: str | None = None
    device_id: str | None = None
    provider: str | None = None
    mcp_server_id: str | None = None
    minimum_confidence: Confidence = Confidence.medium
    limit: int = Field(default=50, ge=1, le=500)
    cursor: str | None = None

    @model_validator(mode="after")
    def valid_range(self) -> RangeInput:
        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("timestamps require an offset")
        if self.start_time >= self.end_time:
            raise ValueError("start_time must precede end_time")
        return self


class ApprovalInput(StrictModel):
    asset_id: str | None = None
    asset_type: str | None = None
    name: str | None = None
    endpoint: str | None = None

    @model_validator(mode="after")
    def has_lookup(self) -> ApprovalInput:
        if not any((self.asset_id, self.name, self.endpoint)):
            raise ValueError("asset_id, name, or endpoint is required")
        return self


class ConnectorFreshness(StrictModel):
    source_type: str
    health: str
    last_success: datetime | None = None
    latest_observation: datetime | None = None
    stale: bool
    error_code: str | None = None


class ExplanationDetails(StrictModel):
    what_was_observed: str
    expected_route: str | None
    why_flagged: list[str]
    evidence_used: list[str]
    evidence_not_available: list[str]
    confidence_explanation: str
    likely_false_positives: list[str]
    recommended_steps: list[str]


class ApprovalDetails(StrictModel):
    match_method: str | None
    ambiguous: bool
    approval_status: str | None = None
    expired: bool | None = None
    required_route: str | None = None
    owner: str | None = None
    risk_tier: str | None = None


class ToolResponse(StrictModel):
    observed_facts: list[str] = Field(default_factory=list)
    inferred_conclusions: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    finding: Finding | None = None
    asset: RegistryAsset | None = None
    assets: list[RegistryAsset] = Field(default_factory=list)
    next_cursor: str | None = None
    active_filters: dict[str, Any] = Field(default_factory=dict)
    telemetry_freshness: dict[str, ConnectorFreshness] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    details: ExplanationDetails | ApprovalDetails | None = None
    error: ErrorResponse | None = None


class ErrorResponse(StrictModel):
    code: str
    message: str
    correlation_id: str
