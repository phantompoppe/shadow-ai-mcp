from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from opentelemetry import trace
from pydantic import ValidationError

from shadow_ai_mcp.auth.core import SecurityError, current_principal, require
from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.models.schemas import (
    ApprovalDetails,
    ApprovalInput,
    Confidence,
    ErrorResponse,
    ExplanationDetails,
    Finding,
    RangeInput,
    SearchInput,
    ToolResponse,
)
from shadow_ai_mcp.normalization.core import domain_of
from shadow_ai_mcp.observability.context import correlation_id as context_correlation_id
from shadow_ai_mcp.registry.matching import match_assets
from shadow_ai_mcp.storage.repository import Repository


class InvestigationService:
    def __init__(self, repository: Repository, settings: Settings):
        self.repository = repository
        self.settings = settings

    def execute(
        self, name: str, filters: dict[str, Any], action: Callable[[], ToolResponse]
    ) -> ToolResponse:
        started = time.monotonic()
        correlation_id = context_correlation_id.get() or uuid.uuid4().hex
        principal = current_principal.get()
        result_count = 0
        outcome = "success"
        try:
            require("shadow_ai:read")
            response = action()
            result_count = len(response.findings) or int(response.finding is not None)
            return response
        except (ValidationError, ValueError) as exc:
            outcome = (
                "INVALID_REQUEST"
                if not isinstance(exc, ValueError) or str(exc) != "QUERY_RANGE_TOO_LARGE"
                else "QUERY_RANGE_TOO_LARGE"
            )
        except SecurityError as exc:
            outcome = exc.code
        except KeyError:
            outcome = "NOT_FOUND"
        except Exception:
            outcome = "INTERNAL_ERROR"
        finally:
            span = trace.get_current_span()
            span.set_attribute("shadow.tool", name)
            span.set_attribute("shadow.outcome", outcome)
            safe_filters = {
                k: (
                    str(v)[:64]
                    if k == "limit"
                    else "sha256:" + hashlib.sha256(str(v).encode()).hexdigest()
                )
                for k, v in filters.items()
                if k not in {"cursor", "authorization", "token"} and v is not None
            }
            self.repository.audit(
                audit_id=uuid.uuid4().hex,
                occurred_at=datetime.now(UTC),
                tool_name=name,
                caller_id=principal.identity if principal else "unauthenticated",
                correlation_id=correlation_id,
                duration_ms=int((time.monotonic() - started) * 1000),
                filters=safe_filters,
                result_count=result_count,
                outcome=outcome,
            )
        return ToolResponse(
            error=ErrorResponse(
                code=outcome,
                message={
                    "INVALID_REQUEST": "Invalid request parameters",
                    "QUERY_RANGE_TOO_LARGE": "Time range exceeds configured limit",
                    "UNAUTHENTICATED": "Authentication required",
                    "FORBIDDEN": "Insufficient scope",
                    "NOT_FOUND": "Finding not found",
                    "INTERNAL_ERROR": "Request failed",
                }.get(outcome, "Request failed"),
                correlation_id=correlation_id,
            )
        )

    def _context(self) -> tuple[dict[str, Any], list[str]]:
        return self.repository.freshness(self.settings.freshness_seconds)

    def search(self, query: SearchInput) -> ToolResponse:
        if query.limit > self.settings.maximum_result_limit:
            raise ValueError("limit exceeds maximum")
        results, cursor = self.repository.search(query)
        freshness, warnings = self._context()
        return ToolResponse(
            findings=[self._redact_evidence(f) for f in results],
            next_cursor=cursor,
            telemetry_freshness=freshness,
            warnings=warnings,
            active_filters=query.model_dump(mode="json", exclude_none=True, exclude={"cursor"}),
            observed_facts=[f"{len(results)} persisted findings matched"],
        )

    @staticmethod
    def _redact_evidence(finding: Finding) -> Finding:
        principal = require("shadow_ai:read")
        if "shadow_ai:evidence:read" in principal.scopes or "shadow_ai:admin" in principal.scopes:
            return finding
        copy = finding.model_copy(deep=True)
        copy.evidence_references = [
            "sha256:" + hashlib.sha256(ref.encode()).hexdigest()
            for ref in finding.evidence_references
        ]
        return copy

    def get(self, finding_id: str) -> ToolResponse:
        finding = self.repository.finding(finding_id)
        if not finding:
            raise KeyError(finding_id)
        freshness, warnings = self._context()
        return ToolResponse(
            finding=self._redact_evidence(finding),
            asset=self.repository.asset(finding.asset_id),
            telemetry_freshness=freshness,
            warnings=warnings,
            observed_facts=["Persisted finding and linked evidence references returned"],
            inferred_conclusions=[finding.summary],
        )

    def explain(self, finding_id: str) -> ToolResponse:
        response = self.get(finding_id)
        finding = response.finding
        assert finding is not None
        response.details = ExplanationDetails.model_validate(
            {
                "what_was_observed": (
                    f"{finding.summary}; first seen {finding.first_seen.isoformat()}"
                ),
                "expected_route": finding.required_route,
                "why_flagged": finding.reason_codes,
                "evidence_used": finding.evidence_references,
                "evidence_not_available": response.warnings
                or ["No further evidence in this read-only index"],
                "confidence_explanation": finding.explanation,
                "likely_false_positives": [
                    "NAT or shared egress identity mismatch",
                    "Delayed or missing gateway/proxy telemetry",
                    "Undocumented direct-route exception or stale registry",
                ],
                "recommended_steps": finding.recommended_investigation_steps,
            }
        )
        return response

    def range_search(self, query: RangeInput, mcp: bool) -> ToolResponse:
        if query.end_time - query.start_time > timedelta(hours=self.settings.maximum_range_hours):
            raise ValueError("QUERY_RANGE_TOO_LARGE")
        detection_ids = ["SHAI-003", "SHAI-004"] if mcp else ["SHAI-001", "SHAI-002"]
        ordering = [Confidence.low, Confidence.medium, Confidence.high]
        search = SearchInput(
            detection_ids=detection_ids,
            confidence_levels=ordering[ordering.index(query.minimum_confidence) :],
            user_id=query.user_id,
            device_id=query.device_id if not mcp else None,
            provider=query.provider if not mcp else None,
            mcp_server_id=query.mcp_server_id if mcp else None,
            first_seen_after=query.start_time,
            last_seen_before=query.end_time,
            limit=query.limit,
            cursor=query.cursor,
        )
        return self.search(search)

    def approval(self, query: ApprovalInput) -> ToolResponse:
        assets = self.repository.assets()
        matches = match_assets(
            assets,
            asset_id=query.asset_id,
            asset_type=query.asset_type,
            name=query.name,
            endpoint=query.endpoint,
            domain=domain_of(query.endpoint),
        )
        freshness, warnings = self._context()
        if len(matches) > 1:
            warnings.append("Multiple registry assets match; inspect asset IDs")
        now = datetime.now(UTC)
        details: dict[str, Any] = {
            "match_method": matches[0].method if matches else None,
            "ambiguous": len(matches) > 1,
        }
        if matches:
            asset = matches[0].asset
            details.update(
                approval_status=asset.approval_status,
                expired=bool(asset.expiration_date and asset.expiration_date < now),
                required_route=asset.required_route,
                owner=asset.owner,
                risk_tier=asset.risk_tier,
            )
        return ToolResponse(
            asset=matches[0].asset if matches else None,
            assets=[m.asset for m in matches],
            details=ApprovalDetails.model_validate(details),
            telemetry_freshness=freshness,
            warnings=warnings,
            observed_facts=[f"{len(matches)} registry matches"],
            inferred_conclusions=["No match in the current registry snapshot"]
            if not matches
            else [],
        )
