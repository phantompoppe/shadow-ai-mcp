from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta

from opentelemetry import trace
from sqlalchemy import text

from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.connectors.base import Connector
from shadow_ai_mcp.detections.engine import detect
from shadow_ai_mcp.observability.metrics import (
    CONNECTOR_SYNCS,
    DETECTION_DURATION,
    FINDINGS,
    OBSERVATIONS,
    TELEMETRY_AGE,
)
from shadow_ai_mcp.storage.db import DetectionRunRow
from shadow_ai_mcp.storage.repository import Repository

logger = logging.getLogger(__name__)


class Worker:
    def __init__(self, repository: Repository, connectors: list[Connector], settings: Settings):
        self.repository = repository
        self.connectors = connectors
        self.settings = settings
        self._local_locks = {c.config.connector_id: asyncio.Lock() for c in connectors}

    async def sync(self, connector: Connector) -> int:
        connector_id = connector.config.connector_id
        lock = self._local_locks[connector_id]
        if lock.locked():
            return 0
        async with lock:
            # Session-level PG advisory lock prevents overlap across service processes.
            with self.repository.db.engine.connect() as connection:
                pg = connection.dialect.name == "postgresql"
                key = int.from_bytes(
                    hashlib.sha256(connector_id.encode()).digest()[:8], "big", signed=True
                )
                if (
                    pg
                    and not connection.execute(
                        text("SELECT pg_try_advisory_lock(:key)"), {"key": key}
                    ).scalar()
                ):
                    return 0
                try:
                    with trace.get_tracer(__name__).start_as_current_span(
                        "shadow.connector.sync"
                    ) as span:
                        span.set_attribute("shadow.source_type", connector.config.source_type)
                        return await self._sync_locked(connector)
                finally:
                    if pg:
                        connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})

    async def _sync_locked(self, connector: Connector) -> int:
        config = connector.config
        self.repository.save_connector(
            config.connector_id, config.source_type, config.mapping_version
        )
        state = self.repository.sync_state(config.connector_id)
        checkpoint = (
            state.checkpoint_time
            if state and state.checkpoint_time
            else (datetime.now(UTC) - timedelta(seconds=self.settings.polling_seconds * 2))
        )
        if checkpoint.tzinfo is None:
            checkpoint = checkpoint.replace(tzinfo=UTC)
        end = datetime.now(UTC)
        # Re-read the overlap window; deterministic IDs make this safe.
        start = checkpoint - timedelta(seconds=self.settings.correlation_seconds)
        cursor = state.cursor if state else None
        ingested = 0
        try:
            for _ in range(config.max_pages):
                batch = await connector.fetch_observations(start, end, cursor, 1000)
                if batch.errors:
                    logger.warning(
                        "connector %s rejected %s records", config.connector_id, len(batch.errors)
                    )
                ingested += self.repository.save_observations(batch.observations)
                if batch.assets:
                    self.repository.save_registry(batch.assets)
                latest = max((o.observed_at for o in batch.observations), default=None)
                if batch.assets:
                    latest = end
                if batch.errors:
                    self.repository.sync_result(
                        config.connector_id,
                        cursor=cursor,
                        checkpoint=checkpoint,
                        latest=latest,
                        error="PARTIAL_BATCH",
                    )
                    CONNECTOR_SYNCS.labels(config.source_type, "partial").inc()
                    return ingested
                # Checkpoint the page only after its writes succeed. Cursor recovery replays safely.
                self.repository.sync_result(
                    config.connector_id,
                    cursor=batch.next_cursor,
                    checkpoint=checkpoint if batch.next_cursor else end,
                    latest=latest,
                    error=None,
                )
                OBSERVATIONS.labels(config.source_type).inc(len(batch.observations))
                if not batch.next_cursor:
                    CONNECTOR_SYNCS.labels(config.source_type, "success").inc()
                    return ingested
                if batch.next_cursor == cursor:
                    raise ValueError("connector returned repeated cursor")
                cursor = batch.next_cursor
            raise ValueError("connector exceeded max_pages")
        except Exception as exc:
            category = (
                connector._error(exc) if hasattr(connector, "_error") else "CONNECTOR_UNAVAILABLE"
            )
            self.repository.sync_result(
                config.connector_id,
                cursor=cursor,
                checkpoint=checkpoint,
                latest=None,
                error=category,
            )
            CONNECTOR_SYNCS.labels(config.source_type, "error").inc()
            logger.warning("connector %s sync failed: %s", config.connector_id, category)
            return ingested

    def run_detections(self) -> tuple[int, int]:
        run_id = uuid.uuid4().hex
        started = datetime.now(UTC)
        with self.repository.db.session() as session:
            session.add(DetectionRunRow(run_id=run_id, started_at=started, status="running"))
        try:
            with (
                DETECTION_DURATION.time(),
                trace.get_tracer(__name__).start_as_current_span("shadow.detection.run"),
            ):
                freshness, _ = self.repository.freshness(self.settings.freshness_seconds)
                for state in freshness.values():
                    stamp = state["last_success"]
                    if stamp:
                        TELEMETRY_AGE.labels(state["source_type"]).set(
                            max(
                                0,
                                (datetime.now(UTC) - datetime.fromisoformat(stamp)).total_seconds(),
                            )
                        )
                observations = self.repository.observations(
                    started - timedelta(days=self.settings.observation_retention_days), started
                )
                pairs = detect(
                    observations,
                    self.repository.assets(),
                    freshness,
                    window_seconds=self.settings.correlation_seconds,
                    shared_egress_ips=self.settings.shared_egress_ips,
                    allowed_exceptions=self.settings.allowed_route_exceptions,
                )
                created, updated = self.repository.save_findings(pairs)
            for finding, _ in pairs:
                FINDINGS.labels("evaluated", finding.detection_id).inc()
            with self.repository.db.session() as session:
                row = session.get(DetectionRunRow, run_id)
                if row:
                    row.status, row.finished_at = "success", datetime.now(UTC)
                    row.findings_created, row.findings_updated = created, updated
            return created, updated
        except Exception:
            with self.repository.db.session() as session:
                row = session.get(DetectionRunRow, run_id)
                if row:
                    row.status, row.finished_at = "error", datetime.now(UTC)
                    row.error_code = "INTERNAL_ERROR"
            raise

    async def cycle(self) -> tuple[int, int]:
        for connector in self.connectors:
            await self.sync(connector)
        result = self.run_detections()
        self.repository.retain(
            self.settings.observation_retention_days, self.settings.finding_retention_days
        )
        return result

    async def loop(self) -> None:
        while True:
            started = time.monotonic()
            try:
                await self.cycle()
            except Exception:
                logger.exception("worker cycle failed")
            await asyncio.sleep(
                max(5, self.settings.polling_seconds - (time.monotonic() - started))
            )

    async def close(self) -> None:
        for connector in self.connectors:
            await connector.close()
