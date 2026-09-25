"""Read-only, same-origin investigation UI over the existing service layer."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from time import monotonic

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.models.schemas import ApprovalInput, SearchInput, ToolResponse
from shadow_ai_mcp.observability.context import correlation_id
from shadow_ai_mcp.observability.metrics import UI_DURATION
from shadow_ai_mcp.tools.service import InvestigationService

logger = logging.getLogger(__name__)
ASSETS = Path(__file__).with_name("ui")
SAFE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
}
ERROR_STATUS = {
    "INVALID_REQUEST": 400,
    "QUERY_RANGE_TOO_LARGE": 400,
    "UNAUTHENTICATED": 401,
    "FORBIDDEN": 403,
    "NOT_FOUND": 404,
    "RATE_LIMITED": 429,
}
LIST_FILTERS = {"detection_ids", "statuses", "severities", "confidence_levels"}
SCALAR_FILTERS = {
    "user_id",
    "device_id",
    "provider",
    "destination",
    "mcp_server_id",
    "first_seen_after",
    "last_seen_before",
    "limit",
    "cursor",
}


async def body_fields(request: Request, allowed: set[str]) -> dict[str, object]:
    """Bound request data before Pydantic validation and database work."""
    if request.headers.get("content-type", "").split(";")[0] != "application/json":
        raise ValueError("JSON content type required")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 4096:
            raise ValueError("request too large")
        body.extend(chunk)
    parsed = json.loads(body)
    if not isinstance(parsed, dict) or len(parsed) > 14 or set(parsed) - allowed:
        raise ValueError("invalid request fields")
    for key, value in parsed.items():
        if key in LIST_FILTERS:
            if not isinstance(value, list) or len(value) > 8:
                raise ValueError("invalid list filter")
            values = value
        else:
            values = [value]
        if any(
            not isinstance(item, (str, int))
            or isinstance(item, bool)
            or len(str(item)) > (1024 if key == "endpoint" else 512)
            for item in values
        ):
            raise ValueError("invalid filter value")
    return parsed


def build_ui(service: InvestigationService, settings: Settings) -> Starlette:
    async def invoke(
        name: str, filters: dict[str, object], action: Callable[[], ToolResponse]
    ) -> JSONResponse:
        started = monotonic()
        outcome = "INTERNAL_ERROR"
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(service.execute, name, filters, action),
                timeout=settings.request_timeout_seconds,
            )
            outcome = response.error.code if response.error else "success"
            return JSONResponse(
                response.model_dump(mode="json"),
                status_code=ERROR_STATUS.get(outcome, 500) if response.error else 200,
                headers=SAFE_HEADERS,
            )
        except TimeoutError:
            outcome = "RATE_LIMITED"
            return JSONResponse(
                {"error": {"code": outcome, "message": "Request timeout"}},
                status_code=504,
                headers=SAFE_HEADERS,
            )
        except Exception:
            logger.warning("UI request failed")
            return JSONResponse(
                {
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Request failed",
                        "correlation_id": correlation_id.get(),
                    }
                },
                status_code=500,
                headers=SAFE_HEADERS,
            )
        finally:
            UI_DURATION.labels(name, outcome).observe(monotonic() - started)

    async def page(request: Request) -> Response:
        return FileResponse(ASSETS / "index.html", media_type="text/html", headers=SAFE_HEADERS)

    async def stylesheet(request: Request) -> Response:
        return FileResponse(ASSETS / "app.css", media_type="text/css", headers=SAFE_HEADERS)

    async def script(request: Request) -> Response:
        return FileResponse(ASSETS / "app.js", media_type="text/javascript", headers=SAFE_HEADERS)

    async def findings(request: Request) -> Response:
        try:
            filters = await body_fields(request, LIST_FILTERS | SCALAR_FILTERS)
        except ValueError:
            filters = {"invalid_query": "rejected"}

        def action() -> ToolResponse:
            query = SearchInput.model_validate(filters)
            if query.limit > settings.maximum_result_limit:
                query = query.model_copy(update={"limit": settings.maximum_result_limit})
            start, end = query.first_seen_after, query.last_seen_before
            if bool(start) != bool(end):
                raise ValueError("both time bounds are required")
            if (
                start
                and end
                and (start >= end or end - start > timedelta(hours=settings.maximum_range_hours))
            ):
                raise ValueError("QUERY_RANGE_TOO_LARGE")
            return service.search(query)

        return await invoke("ui_search_findings", filters, action)

    async def finding(request: Request) -> Response:
        finding_id = request.path_params["finding_id"]

        def action() -> ToolResponse:
            if not re.fullmatch(r"[0-9a-f]{64}", finding_id):
                raise ValueError("invalid finding ID")
            return service.get(finding_id)

        return await invoke("ui_get_finding", {"finding_id": finding_id}, action)

    async def explanation(request: Request) -> Response:
        finding_id = request.path_params["finding_id"]

        def action() -> ToolResponse:
            if not re.fullmatch(r"[0-9a-f]{64}", finding_id):
                raise ValueError("invalid finding ID")
            return service.explain(finding_id)

        return await invoke("ui_explain_finding", {"finding_id": finding_id}, action)

    async def approval(request: Request) -> Response:
        try:
            filters = await body_fields(request, {"asset_id", "asset_type", "name", "endpoint"})
        except ValueError:
            filters = {"invalid_query": "rejected"}

        def action() -> ToolResponse:
            query = ApprovalInput.model_validate(filters)
            if query.endpoint and ("?" in query.endpoint or "#" in query.endpoint):
                raise ValueError("endpoint query or fragment is not allowed")
            return service.approval(query)

        return await invoke("ui_check_approval", filters, action)

    return Starlette(
        routes=[
            Route("/", page),
            Route("/app.css", stylesheet),
            Route("/app.js", script),
            Route("/api/findings", findings, methods=["POST"]),
            Route("/api/findings/{finding_id}/explanation", explanation),
            Route("/api/findings/{finding_id}", finding),
            Route("/api/approval", approval, methods=["POST"]),
        ]
    )
