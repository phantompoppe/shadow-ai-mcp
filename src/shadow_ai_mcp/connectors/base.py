from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from shadow_ai_mcp.models.schemas import Observation, RegistryAsset, StrictModel
from shadow_ai_mcp.normalization.core import ALLOWED_FIELDS, PROHIBITED


class ConnectorConfig(StrictModel):
    connector_id: str
    source_type: Literal["siem", "llm_proxy", "mcp_gateway", "registry"]
    kind: Literal["fixture", "http", "file"]
    enabled: bool = True
    endpoint: str | None = None
    fixture_path: str | None = None
    file_path: str | None = None
    secret_env: str | None = None
    secret_file: str | None = None
    method: Literal["GET", "POST"] = "GET"
    static_params: dict[str, str] = Field(default_factory=dict)
    field_mapping: dict[str, str] = Field(default_factory=dict)
    records_field: str = "records"
    cursor_field: str = "next_cursor"
    start_param: str = "start_time"
    end_param: str = "end_time"
    cursor_param: str = "cursor"
    limit_param: str = "limit"
    mapping_version: str = "1"
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=2, ge=0, le=5)
    rate_limit_per_second: float = Field(default=5, gt=0, le=100)
    max_pages: int = Field(default=100, ge=1, le=1000)
    health_path: str | None = None

    @model_validator(mode="after")
    def validate_source(self) -> ConnectorConfig:
        if self.kind == "http" and not self.endpoint:
            raise ValueError("HTTP connector requires endpoint")
        if self.kind == "fixture" and not self.fixture_path:
            raise ValueError("fixture connector requires fixture_path")
        if self.kind == "file" and not self.file_path:
            raise ValueError("file connector requires file_path")
        if self.secret_env and self.secret_file:
            raise ValueError("use one secret reference")
        if self.source_type == "registry" and self.kind == "fixture":
            raise ValueError("registry fixtures use the file adapter")
        if any(
            target not in ALLOWED_FIELDS or PROHIBITED.search(target) or PROHIBITED.search(source)
            for target, source in self.field_mapping.items()
        ):
            raise ValueError("field mapping contains unknown or prohibited fields")
        if any(PROHIBITED.search(key) for key in self.static_params):
            raise ValueError("static parameter name is prohibited")
        return self


class ConnectorHealth(StrictModel):
    status: str
    error_code: str | None = None
    checked_at: datetime


class ObservationBatch(StrictModel):
    observations: list[Observation] = Field(default_factory=list)
    assets: list[RegistryAsset] = Field(default_factory=list)
    next_cursor: str | None = None
    errors: list[str] = Field(default_factory=list)
    source_count: int = 0


class Connector(Protocol):
    connector_type: str
    config: ConnectorConfig

    async def test_connection(self) -> ConnectorHealth: ...

    async def fetch_observations(
        self, start_time: datetime, end_time: datetime, cursor: str | None = None, limit: int = 1000
    ) -> ObservationBatch: ...

    async def close(self) -> None: ...


def parse_connectors(document: Any) -> list[ConnectorConfig]:
    if not isinstance(document, dict) or not isinstance(document.get("connectors"), list):
        raise ValueError("connector configuration requires a connectors list")
    configs = [ConnectorConfig.model_validate(row) for row in document["connectors"]]
    ids = [c.connector_id for c in configs]
    if len(ids) != len(set(ids)):
        raise ValueError("connector IDs must be unique")
    return [c for c in configs if c.enabled]
