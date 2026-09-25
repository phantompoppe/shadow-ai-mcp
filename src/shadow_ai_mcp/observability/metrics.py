from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from prometheus_client import Counter, Gauge, Histogram

from shadow_ai_mcp.observability.context import correlation_id

SECRET_PATTERN = re.compile(r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]+|(?:token|password|key)=\S+)")

CONNECTOR_SYNCS = Counter(
    "shadow_connector_sync_total", "Connector sync results", ["source", "outcome"]
)
OBSERVATIONS = Counter("shadow_observation_ingested_total", "Observations", ["source"])
DETECTION_DURATION = Histogram("shadow_detection_duration_seconds", "Detection duration")
FINDINGS = Counter("shadow_findings_total", "Findings", ["operation", "detection"])
MCP_DURATION = Histogram("shadow_mcp_request_seconds", "MCP request duration", ["tool", "outcome"])
AUTH_FAILURES = Counter("shadow_auth_failure_total", "Auth failures", ["category"])
DB_HEALTH = Gauge("shadow_database_health", "Database reachable")
TELEMETRY_AGE = Gauge("shadow_telemetry_age_seconds", "Age of last success", ["source"])


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": SECRET_PATTERN.sub("[REDACTED]", record.getMessage()),
                "correlation_id": correlation_id.get(),
            }
        )


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
