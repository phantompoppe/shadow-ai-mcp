from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from shadow_ai_mcp.models.schemas import Observation

PROHIBITED = re.compile(
    r"(^|[_-])(prompt|response|body|argument|result|authorization|cookie|token|secret|password|api[_-]?key|credential)([_-]|$)",
    re.I,
)
SECRET_VALUE = re.compile(
    r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|(?:api[_-]?key|token|password)=\S+)"
)
ALLOWED_FIELDS = set(Observation.model_fields) - {"observation_id", "ingested_at", "metadata"}
FIELD_LIMITS = {
    "source_event_id": 256,
    "user_id": 256,
    "user_email": 256,
    "service_account_id": 256,
    "device_id": 256,
    "application_id": 256,
    "provider": 128,
    "destination_domain": 256,
    "mcp_server_id": 256,
    "correlation_id": 256,
    "evidence_reference": 512,
}


def safe_text(value: Any, max_length: int = 1024) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    text = str(value).strip()[:max_length]
    return SECRET_VALUE.sub("[REDACTED]", text)


def normalize_url(value: str) -> str:
    value = value.strip()
    parts = urlsplit(value if "://" in value else "https://" + value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("invalid HTTP endpoint")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    port = parts.port
    default_port = (parts.scheme.lower() == "https" and port == 443) or (
        parts.scheme.lower() == "http" and port == 80
    )
    netloc = f"[{host}]" if ":" in host else host
    if port and not default_port:
        netloc += f":{port}"
    # Query values often contain prompt text or credentials; retain only the meaningful path.
    path = parts.path if len(parts.path) <= 256 else "/[REDACTED-LONG-PATH]"
    return urlunsplit((parts.scheme.lower(), netloc, path or "/", "", ""))


def domain_of(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return urlsplit(normalize_url(value)).hostname
    except ValueError:
        return None


def safe_reference(value: Any) -> str | None:
    text = safe_text(value, 512)
    if not text or SECRET_VALUE.search(str(value)) or any(x in text for x in ("?", "#", "@")):
        return None
    if not re.fullmatch(r"[A-Za-z][\w+.-]{1,32}://[\w./:%-]{1,450}", text):
        return None
    return text


def provider_for(domain: str | None, catalog: list[dict[str, Any]]) -> str | None:
    if not domain:
        return None
    for provider in catalog:
        for candidate in (
            provider.get("domains", [])
            + provider.get("api_domains", [])
            + provider.get("web_domains", [])
            + provider.get("regional_domains", [])
        ):
            candidate = str(candidate).lower()
            if domain == candidate or domain.endswith("." + candidate):
                return str(provider["name"]).lower()
    return None


def normalize_observation(
    raw: dict[str, Any],
    *,
    connector_id: str,
    source_type: str,
    mapping: dict[str, str],
    mapping_version: str,
    metadata_allowlist: list[str],
    catalog: list[dict[str, Any]],
    pseudonymization_key_env: str | None = None,
    fixture_now: datetime | None = None,
) -> Observation:
    if any(
        PROHIBITED.search(source) or PROHIBITED.search(target) for target, source in mapping.items()
    ):
        raise ValueError("field mapping includes prohibited content")
    data: dict[str, Any] = {}
    for target, source in mapping.items():
        if target not in ALLOWED_FIELDS:
            raise ValueError("unknown observation mapping field")
        if source in raw:
            data[target] = raw[source]
    if fixture_now and "offset_minutes" in raw:
        data["observed_at"] = fixture_now + timedelta(minutes=int(raw["offset_minutes"]))
    if isinstance(data.get("observed_at"), str):
        data["observed_at"] = datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))
    for key, value in list(data.items()):
        if key != "observed_at":
            data[key] = safe_text(value, FIELD_LIMITS.get(key, 1024))
    for key in ("destination_url", "mcp_server_url"):
        if data.get(key):
            data[key] = normalize_url(data[key])
    data["destination_domain"] = (
        domain_of(data.get("destination_url"))
        or (safe_text(data.get("destination_domain"), 256) or "").lower().rstrip(".")
        or None
    )
    if data.get("user_email"):
        data["user_email"] = data["user_email"].lower()
    if data.get("provider"):
        data["provider"] = data["provider"].lower()
    else:
        data["provider"] = provider_for(data["destination_domain"], catalog)
    if data.get("source_ip"):
        data["source_ip"] = str(ipaddress.ip_address(data["source_ip"]))
    pseudonym_key = os.getenv(pseudonymization_key_env) if pseudonymization_key_env else None
    if pseudonymization_key_env and not pseudonym_key:
        raise ValueError("pseudonymization key environment variable is unavailable")
    if pseudonym_key:
        for field in ("user_id", "user_email", "service_account_id"):
            if data.get(field):
                data[field] = hmac.new(
                    pseudonym_key.encode(), data[field].encode(), "sha256"
                ).hexdigest()
    reference = safe_reference(data.get("evidence_reference"))
    data["evidence_reference"] = reference
    data["evidence_hash"] = hashlib.sha256(reference.encode()).hexdigest() if reference else None
    metadata = {
        name: safe_text(raw[name], 256)
        for name in metadata_allowlist
        if name in raw and not PROHIBITED.search(name) and not SECRET_VALUE.search(str(raw[name]))
    }
    data["metadata"] = metadata
    data.update(source_type=source_type, connector_id=connector_id, mapping_version=mapping_version)
    if not data.get("event_type") or not data.get("observed_at"):
        raise ValueError("event_type and observed_at are required")
    # Stable event IDs make replay and cursor recovery idempotent.
    source_field = mapping.get("source_event_id")
    raw_source_id = raw.get(source_field) if source_field else None
    identity = (safe_text(raw_source_id, 4096) if raw_source_id is not None else None) or "|".join(
        str(data.get(k) or "")
        for k in (
            "event_type",
            "observed_at",
            "user_id",
            "device_id",
            "source_ip",
            "destination_url",
            "mcp_server_url",
            "correlation_id",
            "route_type",
        )
    )
    data["observation_id"] = hashlib.sha256(f"{connector_id}|{identity}".encode()).hexdigest()
    return Observation.model_validate(data)
