from __future__ import annotations

import asyncio
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from shadow_ai_mcp.config.settings import load_document
from shadow_ai_mcp.connectors.base import ConnectorConfig, ConnectorHealth, ObservationBatch
from shadow_ai_mcp.models.schemas import RegistryAsset
from shadow_ai_mcp.normalization.core import (
    PROHIBITED,
    SECRET_VALUE,
    normalize_observation,
    normalize_url,
    safe_text,
)


def sanitize_asset(asset: RegistryAsset, metadata_allowlist: list[str]) -> RegistryAsset:
    asset.canonical_endpoint = normalize_url(asset.canonical_endpoint)
    asset.alternate_endpoints = [normalize_url(value) for value in asset.alternate_endpoints]
    asset.owner = safe_text(asset.owner, 256)
    asset.business_purpose = safe_text(asset.business_purpose, 512)
    asset.metadata = {
        k: safe_text(v, 256)
        for k, v in asset.metadata.items()
        if k in metadata_allowlist and not PROHIBITED.search(k) and not SECRET_VALUE.search(str(v))
    }
    return asset


class QueryConnector:
    def __init__(
        self,
        config: ConnectorConfig,
        catalog: list[dict[str, Any]],
        metadata_allowlist: list[str],
        pseudonymization_key_env: str | None,
    ):
        self.config = config
        self.connector_type: str = str(config.source_type)
        self.catalog = catalog
        self.metadata_allowlist = metadata_allowlist
        self.pseudonymization_key_env = pseudonymization_key_env
        self._client: httpx.AsyncClient | None = None
        self._last_request = 0.0

    def _secret(self) -> str | None:
        if self.config.secret_env:
            value = os.getenv(self.config.secret_env)
        elif self.config.secret_file:
            value = Path(self.config.secret_file).read_text(encoding="utf-8").strip()
        else:
            return None
        if not value:
            raise ValueError("connector secret reference is unavailable")
        return value

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout_seconds, follow_redirects=False
            )
        return self._client

    async def test_connection(self) -> ConnectorHealth:
        try:
            if self.config.kind in {"fixture", "file"}:
                path = self.config.fixture_path or self.config.file_path
                if not path or not Path(path).is_file():
                    raise FileNotFoundError
            else:
                await self._request(None, health=True)
            return ConnectorHealth(status="healthy", checked_at=datetime.now(UTC))
        except (OSError, ValueError, httpx.HTTPError) as exc:
            return ConnectorHealth(
                status="error", error_code=self._error(exc), checked_at=datetime.now(UTC)
            )

    @staticmethod
    def _error(exc: Exception) -> str:
        if isinstance(exc, httpx.TimeoutException):
            return "CONNECTOR_TIMEOUT"
        if isinstance(exc, httpx.HTTPStatusError):
            return (
                "AUTH_FAILED"
                if exc.response.status_code in {401, 403}
                else (
                    "RATE_LIMITED" if exc.response.status_code == 429 else "CONNECTOR_UNAVAILABLE"
                )
            )
        return "CONNECTOR_UNAVAILABLE"

    async def _request(self, params: dict[str, Any] | None, *, health: bool = False) -> Any:
        client = await self._http()
        if not self.config.endpoint:
            raise ValueError("missing endpoint")
        headers = {"Accept": "application/json"}
        secret = self._secret()
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        endpoint = self.config.endpoint
        if health and self.config.health_path:
            endpoint = endpoint.rstrip("/") + "/" + self.config.health_path.lstrip("/")
        for attempt in range(self.config.retries + 1):
            delay = max(
                0, 1 / self.config.rate_limit_per_second - (time.monotonic() - self._last_request)
            )
            if delay:
                await asyncio.sleep(delay)
            self._last_request = time.monotonic()
            try:
                if self.config.method == "POST" and not health:
                    response = await client.post(endpoint, json=params, headers=headers)
                else:
                    response = await client.get(endpoint, params=params, headers=headers)
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as exc:
                retryable = not isinstance(exc, httpx.HTTPStatusError) or (
                    exc.response.status_code in {429, 500, 502, 503, 504}
                )
                if not retryable or attempt == self.config.retries:
                    raise
                await asyncio.sleep(min(2**attempt, 8))
        raise RuntimeError("unreachable")

    async def fetch_observations(
        self, start_time: datetime, end_time: datetime, cursor: str | None = None, limit: int = 1000
    ) -> ObservationBatch:
        if self.config.kind in {"fixture", "file"}:
            path = self.config.fixture_path or self.config.file_path
            document = load_document(Path(path or ""))
            if self.config.source_type == "registry":
                values = document.get("assets", []) if isinstance(document, dict) else []
                file_assets = [
                    sanitize_asset(RegistryAsset.model_validate(value), self.metadata_allowlist)
                    for value in values
                ]
                return ObservationBatch(assets=file_assets, source_count=len(file_assets))
            records = document.get("records", []) if isinstance(document, dict) else []
            start = int(cursor or 0)
            selected = records[start : start + limit]
            next_cursor = (
                str(start + len(selected)) if start + len(selected) < len(records) else None
            )
            fixture_now = datetime.now(UTC)
        else:
            if any(PROHIBITED.search(key) for key in self.config.static_params):
                raise ValueError("static parameters include prohibited fields")
            params: dict[str, Any] = dict(self.config.static_params)
            params[self.config.start_param] = start_time.isoformat()
            params[self.config.end_param] = end_time.isoformat()
            params[self.config.limit_param] = limit
            if cursor:
                params[self.config.cursor_param] = cursor
            document = await self._request(params)
            if not isinstance(document, dict):
                raise ValueError("malformed connector response")
            records = document.get(self.config.records_field, [])
            if not isinstance(records, list):
                raise ValueError("malformed records array")
            if len(records) > limit:
                raise ValueError("connector exceeded page limit")
            selected = records
            next_cursor = document.get(self.config.cursor_field)
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or len(next_cursor) > 1024
            ):
                raise ValueError("invalid source cursor")
            fixture_now = None
        if self.config.source_type == "registry":
            assets: list[RegistryAsset] = []
            errors: list[str] = []
            for index, record in enumerate(selected):
                try:
                    asset = sanitize_asset(
                        RegistryAsset.model_validate(record), self.metadata_allowlist
                    )
                    assets.append(asset)
                except (ValueError, TypeError):
                    errors.append(f"invalid registry record {index}")
            return ObservationBatch(
                assets=assets, next_cursor=next_cursor, errors=errors, source_count=len(selected)
            )
        observations = []
        errors = []
        for index, record in enumerate(selected):
            try:
                if not isinstance(record, dict):
                    raise ValueError("record must be an object")
                observations.append(
                    normalize_observation(
                        record,
                        connector_id=self.config.connector_id,
                        source_type=self.config.source_type,
                        mapping=self.config.field_mapping,
                        mapping_version=self.config.mapping_version,
                        metadata_allowlist=self.metadata_allowlist,
                        catalog=self.catalog,
                        pseudonymization_key_env=self.pseudonymization_key_env,
                        fixture_now=fixture_now,
                    )
                )
            except (ValueError, TypeError):
                errors.append(f"invalid source record {index}")
        return ObservationBatch(
            observations=observations,
            next_cursor=next_cursor,
            errors=errors,
            source_count=len(selected),
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()


class SIEMConnector(QueryConnector):
    connector_type = "siem"


class LLMProxyConnector(QueryConnector):
    connector_type = "llm_proxy"


class MCPGatewayConnector(QueryConnector):
    connector_type = "mcp_gateway"


class RegistryConnector(QueryConnector):
    connector_type = "registry"


ADAPTERS = {
    "siem": SIEMConnector,
    "llm_proxy": LLMProxyConnector,
    "mcp_gateway": MCPGatewayConnector,
    "registry": RegistryConnector,
}
