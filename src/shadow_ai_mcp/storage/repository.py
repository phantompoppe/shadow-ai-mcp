from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select

from shadow_ai_mcp.models.schemas import Finding, Observation, RegistryAsset, SearchInput
from shadow_ai_mcp.normalization.core import domain_of, normalize_url
from shadow_ai_mcp.storage.db import (
    AuditRow,
    ConnectorRow,
    Database,
    EvidenceRow,
    FindingRow,
    ObservationRow,
    RegistryRow,
    SyncStateRow,
)


def cursor_encode(row: FindingRow) -> str:
    stamp = row.last_seen if row.last_seen.tzinfo else row.last_seen.replace(tzinfo=UTC)
    return (
        base64.urlsafe_b64encode(json.dumps([stamp.isoformat(), row.finding_id]).encode())
        .decode()
        .rstrip("=")
    )


def cursor_decode(cursor: str) -> tuple[datetime, str]:
    try:
        if len(cursor) > 512:
            raise ValueError("cursor too long")
        timestamp, identity = json.loads(
            base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        )
        value = datetime.fromisoformat(timestamp)
        if value.tzinfo is None or not isinstance(identity, str) or len(identity) > 64:
            raise ValueError("invalid cursor")
        return value, identity
    except (ValueError, TypeError, KeyError) as exc:
        raise ValueError("invalid pagination cursor") from exc


class Repository:
    def __init__(self, db: Database):
        self.db = db

    def save_connector(self, connector_id: str, source_type: str, mapping_version: str) -> None:
        with self.db.session() as session:
            row = session.get(ConnectorRow, connector_id)
            if row is None:
                session.add(
                    ConnectorRow(
                        connector_id=connector_id,
                        source_type=source_type,
                        mapping_version=mapping_version,
                    )
                )

    def sync_state(self, connector_id: str) -> SyncStateRow | None:
        with self.db.session() as session:
            return session.get(SyncStateRow, connector_id)

    def sync_result(
        self,
        connector_id: str,
        *,
        cursor: str | None,
        checkpoint: datetime,
        latest: datetime | None,
        error: str | None = None,
    ) -> None:
        with self.db.session() as session:
            row = session.get(ConnectorRow, connector_id)
            if row is None:
                raise ValueError("unknown connector")
            row.last_attempt = datetime.now(UTC)
            row.health = "error" if error else "healthy"
            row.error_code = error
            if not error:
                row.last_success = row.last_attempt
                if latest and (not row.latest_observation or latest > row.latest_observation):
                    row.latest_observation = latest
                state = session.get(SyncStateRow, connector_id)
                if state is None:
                    state = SyncStateRow(connector_id=connector_id)
                    session.add(state)
                state.cursor = cursor
                state.checkpoint_time = checkpoint
                state.updated_at = datetime.now(UTC)

    def save_observations(self, observations: list[Observation]) -> int:
        count = 0
        with self.db.session() as session:
            for obs in observations:
                if session.get(ObservationRow, obs.observation_id):
                    continue
                session.add(
                    ObservationRow(
                        observation_id=obs.observation_id,
                        connector_id=obs.connector_id,
                        source_type=obs.source_type,
                        source_event_id=obs.source_event_id,
                        observed_at=obs.observed_at,
                        user_id=obs.user_id,
                        device_id=obs.device_id,
                        provider=obs.provider,
                        destination_domain=obs.destination_domain,
                        mcp_server_id=obs.mcp_server_id,
                        correlation_id=obs.correlation_id,
                        data=obs.model_dump(mode="json"),
                    )
                )
                count += 1
        return count

    def observations(self, start: datetime, end: datetime) -> list[Observation]:
        with self.db.session() as session:
            rows = session.scalars(
                select(ObservationRow).where(
                    ObservationRow.observed_at >= start, ObservationRow.observed_at <= end
                )
            ).all()
            return [Observation.model_validate(row.data) for row in rows]

    def save_registry(self, assets: list[RegistryAsset]) -> None:
        with self.db.session() as session:
            for asset in assets:
                row = session.get(RegistryRow, asset.asset_id)
                if row is None:
                    row = RegistryRow(
                        asset_id=asset.asset_id,
                        asset_type=asset.asset_type,
                        name=asset.name,
                        canonical_endpoint=asset.canonical_endpoint,
                        approval_status=asset.approval_status,
                        data={},
                    )
                    session.add(row)
                row.asset_type = asset.asset_type
                row.name = asset.name
                row.canonical_endpoint = normalize_url(asset.canonical_endpoint)
                row.endpoint_domain = domain_of(asset.canonical_endpoint)
                row.approval_status = asset.approval_status
                row.expiration_date = asset.expiration_date
                row.updated_at = datetime.now(UTC)
                row.data = asset.model_dump(mode="json")

    def assets(self) -> list[RegistryAsset]:
        with self.db.session() as session:
            return [
                RegistryAsset.model_validate(row.data)
                for row in session.scalars(select(RegistryRow)).all()
            ]

    def asset(self, asset_id: str | None) -> RegistryAsset | None:
        if not asset_id:
            return None
        with self.db.session() as session:
            row = session.get(RegistryRow, asset_id)
            return RegistryAsset.model_validate(row.data) if row else None

    def save_findings(self, pairs: list[tuple[Finding, Observation]]) -> tuple[int, int]:
        created = updated = 0
        with self.db.session() as session:
            for finding, observation in pairs:
                row = session.get(FindingRow, finding.finding_id)
                if row is None:
                    row = FindingRow(
                        finding_id=finding.finding_id,
                        detection_id=finding.detection_id,
                        status="open",
                        severity=finding.severity.value,
                        confidence=finding.confidence.value,
                        first_seen=finding.first_seen,
                        last_seen=finding.last_seen,
                        data={},
                    )
                    session.add(row)
                    created += 1
                else:
                    finding.created_at = Finding.model_validate(row.data).created_at
                    finding.status = row.status
                    updated += 1
                row.detection_id = finding.detection_id
                row.severity = finding.severity.value
                row.confidence = finding.confidence.value
                previous = (
                    row.last_seen if row.last_seen.tzinfo else row.last_seen.replace(tzinfo=UTC)
                )
                row.last_seen = max(finding.last_seen, previous)
                row.user_id = finding.user_id
                row.device_id = finding.device_id
                row.provider = finding.provider
                row.destination = finding.destination
                row.mcp_server_id = finding.mcp_server_id
                row.data = finding.model_dump(mode="json")
                if (
                    session.get(EvidenceRow, (finding.finding_id, observation.observation_id))
                    is None
                ):
                    session.add(
                        EvidenceRow(
                            finding_id=finding.finding_id,
                            observation_id=observation.observation_id,
                            evidence_reference=observation.evidence_reference,
                            evidence_hash=observation.evidence_hash,
                        )
                    )
        return created, updated

    def finding(self, finding_id: str) -> Finding | None:
        with self.db.session() as session:
            row = session.get(FindingRow, finding_id)
            return Finding.model_validate(row.data) if row else None

    def search(self, filters: SearchInput) -> tuple[list[Finding], str | None]:
        query = select(FindingRow)
        fields: dict[str, Any] = {
            "user_id": FindingRow.user_id,
            "device_id": FindingRow.device_id,
            "provider": FindingRow.provider,
            "destination": FindingRow.destination,
            "mcp_server_id": FindingRow.mcp_server_id,
        }
        for key, column in fields.items():
            if value := getattr(filters, key):
                query = query.where(column == value)
        for key, column in (
            ("detection_ids", FindingRow.detection_id),
            ("statuses", FindingRow.status),
            ("severities", FindingRow.severity),
            ("confidence_levels", FindingRow.confidence),
        ):
            if values := getattr(filters, key):
                query = query.where(column.in_([str(value) for value in values]))
        if filters.first_seen_after:
            query = query.where(FindingRow.first_seen >= filters.first_seen_after)
        if filters.last_seen_before:
            query = query.where(FindingRow.last_seen <= filters.last_seen_before)
        if filters.cursor:
            timestamp, identity = cursor_decode(filters.cursor)
            query = query.where(
                or_(
                    FindingRow.last_seen < timestamp,
                    and_(FindingRow.last_seen == timestamp, FindingRow.finding_id < identity),
                )
            )
        query = query.order_by(FindingRow.last_seen.desc(), FindingRow.finding_id.desc())
        with self.db.session() as session:
            rows = session.scalars(query.limit(filters.limit + 1)).all()
            next_cursor = (
                cursor_encode(rows[filters.limit - 1]) if len(rows) > filters.limit else None
            )
            return [Finding.model_validate(row.data) for row in rows[: filters.limit]], next_cursor

    def freshness(self, max_age_seconds: int) -> tuple[dict[str, Any], list[str]]:
        freshness: dict[str, Any] = {}
        warnings: list[str] = []
        with self.db.session() as session:
            for row in session.scalars(select(ConnectorRow)).all():
                latest = row.latest_observation
                success = row.last_success
                if latest and latest.tzinfo is None:
                    latest = latest.replace(tzinfo=UTC)
                if success and success.tzinfo is None:
                    success = success.replace(tzinfo=UTC)
                stale = not success or datetime.now(UTC) - success > timedelta(
                    seconds=max_age_seconds
                )
                freshness[row.connector_id] = {
                    "source_type": row.source_type,
                    "health": row.health,
                    "last_success": success.isoformat() if success else None,
                    "latest_observation": latest.isoformat() if latest else None,
                    "stale": stale,
                    "error_code": row.error_code,
                }
                if stale or row.health != "healthy":
                    warnings.append(f"{row.connector_id}: telemetry stale or unavailable")
        present = {value["source_type"] for value in freshness.values()}
        for source_type in ("siem", "llm_proxy", "mcp_gateway", "registry"):
            if source_type not in present:
                freshness[f"missing:{source_type}"] = {
                    "source_type": source_type,
                    "health": "missing",
                    "last_success": None,
                    "latest_observation": None,
                    "stale": True,
                    "error_code": "NOT_CONFIGURED",
                }
                warnings.append(f"{source_type}: connector not configured")
        return freshness, warnings

    def audit(self, **fields: Any) -> None:
        with self.db.session() as session:
            session.add(AuditRow(**fields))

    def retain(self, observations_days: int, findings_days: int) -> None:
        from sqlalchemy import delete

        with self.db.session() as session:
            old_obs = datetime.now(UTC) - timedelta(days=observations_days)
            old_findings = datetime.now(UTC) - timedelta(days=findings_days)
            session.execute(
                delete(EvidenceRow).where(
                    EvidenceRow.finding_id.in_(
                        select(FindingRow.finding_id).where(FindingRow.last_seen < old_findings)
                    )
                )
            )
            session.execute(delete(FindingRow).where(FindingRow.last_seen < old_findings))
            session.execute(
                delete(EvidenceRow).where(
                    EvidenceRow.observation_id.in_(
                        select(ObservationRow.observation_id).where(
                            ObservationRow.observed_at < old_obs
                        )
                    )
                )
            )
            session.execute(delete(ObservationRow).where(ObservationRow.observed_at < old_obs))
