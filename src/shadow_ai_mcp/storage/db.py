from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


def now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ConnectorRow(Base):
    __tablename__ = "connectors"
    connector_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_type: Mapped[str] = mapped_column(String(40))
    mapping_version: Mapped[str] = mapped_column(String(32))
    health: Mapped[str] = mapped_column(String(24), default="unknown")
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    latest_observation: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))


class SyncStateRow(Base):
    __tablename__ = "connector_sync_state"
    connector_id: Mapped[str] = mapped_column(
        ForeignKey("connectors.connector_id"), primary_key=True
    )
    cursor: Mapped[str | None] = mapped_column(String(1024))
    checkpoint_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ObservationRow(Base):
    __tablename__ = "observations"
    observation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    connector_id: Mapped[str] = mapped_column(String(128), index=True)
    source_type: Mapped[str] = mapped_column(String(40))
    source_event_id: Mapped[str | None] = mapped_column(String(256))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    user_id: Mapped[str | None] = mapped_column(String(256), index=True)
    device_id: Mapped[str | None] = mapped_column(String(256), index=True)
    provider: Mapped[str | None] = mapped_column(String(128), index=True)
    destination_domain: Mapped[str | None] = mapped_column(String(256), index=True)
    mcp_server_id: Mapped[str | None] = mapped_column(String(256), index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(256), index=True)
    data: Mapped[dict[str, object]] = mapped_column(JSON)
    __table_args__ = (Index("ix_observation_connector_event", "connector_id", "source_event_id"),)


class RegistryRow(Base):
    __tablename__ = "registry_assets"
    asset_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    asset_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(256), index=True)
    canonical_endpoint: Mapped[str] = mapped_column(String(1024), index=True)
    endpoint_domain: Mapped[str | None] = mapped_column(String(256), index=True)
    approval_status: Mapped[str] = mapped_column(String(32))
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    data: Mapped[dict[str, object]] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    detection_id: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    severity: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(24))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    user_id: Mapped[str | None] = mapped_column(String(256), index=True)
    device_id: Mapped[str | None] = mapped_column(String(256), index=True)
    provider: Mapped[str | None] = mapped_column(String(128), index=True)
    destination: Mapped[str | None] = mapped_column(String(1024), index=True)
    mcp_server_id: Mapped[str | None] = mapped_column(String(256), index=True)
    data: Mapped[dict[str, object]] = mapped_column(JSON)
    __table_args__ = (Index("ix_finding_last_id", "last_seen", "finding_id"),)


class EvidenceRow(Base):
    __tablename__ = "finding_evidence"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.finding_id"), primary_key=True)
    observation_id: Mapped[str] = mapped_column(
        ForeignKey("observations.observation_id"), primary_key=True
    )
    evidence_reference: Mapped[str | None] = mapped_column(String(1024))
    evidence_hash: Mapped[str | None] = mapped_column(String(64))


class DetectionRunRow(Base):
    __tablename__ = "detection_runs"
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24))
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    findings_updated: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64))


class AuditRow(Base):
    __tablename__ = "audit_events"
    audit_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    tool_name: Mapped[str] = mapped_column(String(80))
    caller_id: Mapped[str] = mapped_column(String(256))
    correlation_id: Mapped[str] = mapped_column(String(64))
    duration_ms: Mapped[int] = mapped_column(Integer)
    filters: Mapped[dict[str, object]] = mapped_column(JSON)
    result_count: Mapped[int] = mapped_column(Integer)
    outcome: Mapped[str] = mapped_column(String(32))


class Database:
    def __init__(self, url: str, statement_timeout_seconds: int = 30):
        options = (
            {"options": f"-c statement_timeout={statement_timeout_seconds * 1000}"}
            if url.startswith("postgresql")
            else {}
        )
        self.engine = create_engine(url, pool_pre_ping=True, connect_args=options)
        self.session_factory = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self.session_factory.begin() as session:
            yield session

    def healthy(self) -> bool:
        from sqlalchemy import text

        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
