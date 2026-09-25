from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHAI_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://shadow@localhost:5432/shadow"
    transport: Literal["streamable-http", "stdio"] = "streamable-http"
    host: str = "127.0.0.1"
    port: int = 8000
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    auth_mode: Literal["jwt", "gateway", "dev"] = "jwt"
    development_mode: bool = False
    dev_trusted_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32", "::1/128"])
    jwt_issuer: str | None = None
    jwt_audience: str | None = None
    jwt_jwks_url: str | None = None
    gateway_trusted_cidrs: list[str] = Field(default_factory=list)
    gateway_identity_header: str = "x-shadow-identity"
    gateway_scopes_header: str = "x-shadow-scopes"
    gateway_assertion_header: str = "x-shadow-assertion"
    gateway_assertion_secret_env: str | None = None
    connectors_file: Path = Path("examples/connectors.yaml")
    catalog_file: Path = Path("examples/provider-catalog.yaml")
    polling_seconds: int = 300
    freshness_seconds: int = 900
    correlation_seconds: int = 120
    maximum_result_limit: int = 100
    maximum_range_hours: int = 24 * 31
    maximum_concurrent_requests: int = 20
    request_timeout_seconds: int = 30
    observation_retention_days: int = 90
    finding_retention_days: int = 365
    pseudonymization_key_env: str | None = None
    metadata_allowlist: list[str] = Field(default_factory=list)
    log_level: str = "INFO"
    run_worker: bool = True
    shared_egress_ips: list[str] = Field(default_factory=list)
    allowed_route_exceptions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def secure_configuration(self) -> Settings:
        if self.auth_mode == "dev" and not self.development_mode:
            raise ValueError("dev authentication requires SHAI_DEVELOPMENT_MODE=true")
        if self.auth_mode == "jwt":
            if not all((self.jwt_issuer, self.jwt_audience, self.jwt_jwks_url)):
                raise ValueError("JWT authentication requires issuer, audience, and JWKS URL")
            if not self.jwt_jwks_url or not self.jwt_jwks_url.startswith("https://"):
                raise ValueError("JWKS URL must use HTTPS")
        if self.auth_mode == "gateway":
            if not self.gateway_trusted_cidrs or not self.gateway_assertion_secret_env:
                raise ValueError(
                    "gateway mode requires trusted CIDRs and an assertion secret env name"
                )
            if not os.getenv(self.gateway_assertion_secret_env):
                raise ValueError("gateway assertion secret environment variable is unavailable")
        if self.pseudonymization_key_env and not os.getenv(self.pseudonymization_key_env):
            raise ValueError("pseudonymization key environment variable is unavailable")
        for cidr in self.gateway_trusted_cidrs + self.dev_trusted_cidrs:
            ipaddress.ip_network(cidr)
        if self.transport == "stdio" and not self.development_mode:
            raise ValueError("stdio is limited to explicit development mode")
        if self.maximum_result_limit > 500 or self.maximum_result_limit < 1:
            raise ValueError("maximum result limit must be between 1 and 500")
        if self.polling_seconds < 5 or self.correlation_seconds < 1:
            raise ValueError("polling/correlation interval is invalid")
        if self.freshness_seconds < 1 or self.maximum_range_hours < 1:
            raise ValueError("freshness or maximum range must be positive")
        if self.maximum_concurrent_requests < 1 or self.request_timeout_seconds < 1:
            raise ValueError("request concurrency and timeout must be positive")
        if self.observation_retention_days < 1 or self.finding_retention_days < 1:
            raise ValueError("retention periods must be positive")
        if not self.development_mode and self.database_url.startswith("sqlite"):
            raise ValueError("SQLite is allowed only in development mode")
        return self


def load_document(path: Path) -> object:
    import yaml

    content = path.read_text(encoding="utf-8")
    return json.loads(content) if path.suffix == ".json" else yaml.safe_load(content)
