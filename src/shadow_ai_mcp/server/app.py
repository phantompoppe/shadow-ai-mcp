from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from opentelemetry import trace
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import TypeAdapter
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from shadow_ai_mcp.auth.core import Authenticator, SecurityError, current_principal
from shadow_ai_mcp.config.settings import Settings, load_document
from shadow_ai_mcp.connectors.adapters import ADAPTERS
from shadow_ai_mcp.connectors.base import Connector, parse_connectors
from shadow_ai_mcp.models.schemas import (
    ApprovalInput,
    Confidence,
    ProviderEntry,
    RangeInput,
    SearchInput,
    Severity,
    ToolResponse,
)
from shadow_ai_mcp.observability.context import correlation_id as context_correlation_id
from shadow_ai_mcp.observability.metrics import (
    AUTH_FAILURES,
    DB_HEALTH,
    MCP_DURATION,
    configure_logging,
)
from shadow_ai_mcp.server.ui import build_ui
from shadow_ai_mcp.storage.db import Database
from shadow_ai_mcp.storage.repository import Repository
from shadow_ai_mcp.tools.service import InvestigationService
from shadow_ai_mcp.workers.runner import Worker

logger = logging.getLogger(__name__)


class RequestGuard:
    def __init__(
        self,
        app: ASGIApp,
        settings: Settings,
        repository: Repository | None = None,
        required_scope: str | None = None,
    ):
        self.app = app
        self.auth = Authenticator(settings)
        self.repository = repository
        self.required_scope = required_scope
        self.semaphore = asyncio.Semaphore(settings.maximum_concurrent_requests)
        self.timeout = settings.request_timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {
            k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])
        }
        peer_ip = scope.get("client", (None, 0))[0]
        try:
            principal = self.auth.authenticate(headers, peer_ip)
        except SecurityError as exc:
            AUTH_FAILURES.labels("unauthenticated").inc()
            if self.repository:
                try:
                    tool = (
                        "ui_access"
                        if str(scope.get("path", "")).startswith("/ui")
                        else headers.get("mcp-name", "mcp_protocol")
                    )
                    if tool not in {
                        "search_shadow_ai",
                        "get_shadow_ai_finding",
                        "explain_shadow_ai_finding",
                        "find_llm_proxy_bypass",
                        "find_mcp_gateway_bypass",
                        "check_ai_approval",
                        "ui_access",
                    }:
                        tool = "mcp_protocol"
                    self.repository.audit(
                        audit_id=uuid.uuid4().hex,
                        occurred_at=datetime.now(UTC),
                        tool_name=tool,
                        caller_id="unauthenticated",
                        correlation_id=uuid.uuid4().hex,
                        duration_ms=0,
                        filters={},
                        result_count=0,
                        outcome=exc.code,
                    )
                except Exception:
                    logger.warning("authentication audit unavailable")
            response = JSONResponse(
                {
                    "code": exc.code,
                    "message": "Authentication required",
                    "correlation_id": uuid.uuid4().hex,
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return
        if self.required_scope and not (
            self.required_scope in principal.scopes or "shadow_ai:admin" in principal.scopes
        ):
            AUTH_FAILURES.labels("forbidden").inc()
            if self.repository:
                try:
                    self.repository.audit(
                        audit_id=uuid.uuid4().hex,
                        occurred_at=datetime.now(UTC),
                        tool_name="ui_access",
                        caller_id=principal.identity,
                        correlation_id=uuid.uuid4().hex,
                        duration_ms=0,
                        filters={},
                        result_count=0,
                        outcome="FORBIDDEN",
                    )
                except Exception:
                    logger.warning("authorization audit unavailable")
            await JSONResponse(
                {
                    "code": "FORBIDDEN",
                    "message": "Insufficient scope",
                    "correlation_id": uuid.uuid4().hex,
                },
                status_code=403,
            )(scope, receive, send)
            return
        try:
            await asyncio.wait_for(self.semaphore.acquire(), timeout=0.01)
        except TimeoutError:
            response = JSONResponse(
                {
                    "code": "RATE_LIMITED",
                    "message": "Server busy",
                    "correlation_id": uuid.uuid4().hex,
                },
                status_code=429,
            )
            await response(scope, receive, send)
            return
        token = current_principal.set(principal)
        correlation_token = context_correlation_id.set(uuid.uuid4().hex)
        started_response = False

        async def safe_send(message: Any) -> None:
            nonlocal started_response
            if message["type"] == "http.response.start":
                started_response = True
            await send(message)

        try:
            await asyncio.wait_for(self.app(scope, receive, safe_send), timeout=self.timeout)
        except TimeoutError:
            logger.warning("MCP request timed out")
            if not started_response:
                await JSONResponse(
                    {
                        "code": "RATE_LIMITED",
                        "message": "Request timeout",
                        "correlation_id": uuid.uuid4().hex,
                    },
                    status_code=504,
                )(scope, receive, send)
        finally:
            current_principal.reset(token)
            context_correlation_id.reset(correlation_token)
            self.semaphore.release()


def build(settings: Settings) -> tuple[MCPServer, Starlette, Worker, InvestigationService]:
    configure_logging(settings.log_level)
    db = Database(settings.database_url, settings.request_timeout_seconds)
    repository = Repository(db)
    document = load_document(settings.connectors_file)
    configs = parse_connectors(document)
    if not settings.development_mode and any(
        c.kind == "http" and (not c.endpoint or not c.endpoint.startswith("https://"))
        for c in configs
    ):
        raise ValueError("production HTTP connectors require HTTPS")
    catalog_document = load_document(settings.catalog_file)
    if not isinstance(catalog_document, dict):
        raise ValueError("provider catalog requires a providers list")
    catalog = [
        entry.model_dump()
        for entry in TypeAdapter(list[ProviderEntry]).validate_python(
            catalog_document.get("providers", [])
        )
    ]
    connectors: list[Connector] = [
        ADAPTERS[c.source_type](
            c, catalog, settings.metadata_allowlist, settings.pseudonymization_key_env
        )
        for c in configs
    ]
    worker = Worker(repository, connectors, settings)
    service = InvestigationService(repository, settings)
    mcp = MCPServer(
        "Shadow AI MCP", description="Read-only shadow AI investigation", version="0.1.0"
    )

    async def call(name: str, args: dict[str, Any], action: Any) -> ToolResponse:
        started = asyncio.get_running_loop().time()
        try:
            with trace.get_tracer(__name__).start_as_current_span("shadow.mcp.tool") as span:
                span.set_attribute("shadow.tool", name)
                # DB calls are synchronous; context variables propagate to the worker thread.
                return await asyncio.wait_for(
                    asyncio.to_thread(service.execute, name, args, action),
                    timeout=settings.request_timeout_seconds,
                )
        finally:
            MCP_DURATION.labels(name, "completed").observe(
                asyncio.get_running_loop().time() - started
            )

    @mcp.tool()
    async def search_shadow_ai(
        detection_ids: list[str] | None = None,
        statuses: list[str] | None = None,
        severities: list[Severity] | None = None,
        confidence_levels: list[Confidence] | None = None,
        user_id: str | None = None,
        device_id: str | None = None,
        provider: str | None = None,
        destination: str | None = None,
        mcp_server_id: str | None = None,
        first_seen_after: datetime | None = None,
        last_seen_before: datetime | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ToolResponse:
        """Search persisted shadow AI findings with stable pagination."""
        args = dict(
            detection_ids=detection_ids,
            statuses=statuses,
            severities=severities,
            confidence_levels=confidence_levels,
            user_id=user_id,
            device_id=device_id,
            provider=provider,
            destination=destination,
            mcp_server_id=mcp_server_id,
            first_seen_after=first_seen_after,
            last_seen_before=last_seen_before,
            limit=limit,
            cursor=cursor,
        )
        return await call(
            "search_shadow_ai", args, lambda: service.search(SearchInput.model_validate(args))
        )

    @mcp.tool()
    async def get_shadow_ai_finding(finding_id: str) -> ToolResponse:
        """Retrieve a finding, its reason codes, evidence references, and registry asset."""
        return await call(
            "get_shadow_ai_finding", {"finding_id": finding_id}, lambda: service.get(finding_id)
        )

    @mcp.tool()
    async def explain_shadow_ai_finding(finding_id: str) -> ToolResponse:
        """Explain the deterministic detection and missing evidence."""
        return await call(
            "explain_shadow_ai_finding",
            {"finding_id": finding_id},
            lambda: service.explain(finding_id),
        )

    @mcp.tool()
    async def find_llm_proxy_bypass(
        start_time: datetime,
        end_time: datetime,
        user_id: str | None = None,
        device_id: str | None = None,
        provider: str | None = None,
        minimum_confidence: Confidence = Confidence.medium,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ToolResponse:
        """Find possible LLM proxy bypass and explicit route policy violations."""
        args = dict(
            start_time=start_time,
            end_time=end_time,
            user_id=user_id,
            device_id=device_id,
            provider=provider,
            minimum_confidence=minimum_confidence,
            limit=limit,
            cursor=cursor,
        )
        return await call(
            "find_llm_proxy_bypass",
            args,
            lambda: service.range_search(RangeInput.model_validate(args), False),
        )

    @mcp.tool()
    async def find_mcp_gateway_bypass(
        start_time: datetime,
        end_time: datetime,
        user_id: str | None = None,
        mcp_server_id: str | None = None,
        minimum_confidence: Confidence = Confidence.medium,
        limit: int = 50,
        cursor: str | None = None,
    ) -> ToolResponse:
        """Find possible MCP gateway bypass and unapproved server activity."""
        args = dict(
            start_time=start_time,
            end_time=end_time,
            user_id=user_id,
            mcp_server_id=mcp_server_id,
            minimum_confidence=minimum_confidence,
            limit=limit,
            cursor=cursor,
        )
        return await call(
            "find_mcp_gateway_bypass",
            args,
            lambda: service.range_search(RangeInput.model_validate(args), True),
        )

    @mcp.tool()
    async def check_ai_approval(
        asset_id: str | None = None,
        asset_type: str | None = None,
        name: str | None = None,
        endpoint: str | None = None,
    ) -> ToolResponse:
        """Check registry approval and expiration for an asset."""
        args = dict(asset_id=asset_id, asset_type=asset_type, name=name, endpoint=endpoint)
        return await call(
            "check_ai_approval", args, lambda: service.approval(ApprovalInput(**args))
        )

    transport = TransportSecuritySettings(allowed_hosts=settings.allowed_hosts)
    mcp_app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=transport,
        max_request_body_size=1024 * 1024,
    )

    async def health(request: Any) -> Response:
        return JSONResponse({"status": "alive"})

    async def ready(request: Any) -> Response:
        good = db.healthy()
        DB_HEALTH.set(1 if good else 0)
        return JSONResponse(
            {"status": "ready" if good else "unavailable"}, status_code=200 if good else 503
        )

    async def metrics(request: Any) -> Response:
        peer = request.client.host if request.client else ""
        if peer not in {"127.0.0.1", "::1"} and not settings.development_mode:
            return Response(status_code=403)
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        task: asyncio.Task[None] | None = None
        async with mcp.session_manager.run():
            if settings.run_worker:
                task = asyncio.create_task(worker.loop())
            try:
                yield
            finally:
                if task:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                await worker.close()
                db.engine.dispose()

    routes: list[BaseRoute] = [
        Route("/healthz", health),
        Route("/readyz", ready),
        Route("/metrics", metrics),
    ]
    if settings.ui_enabled:
        routes.append(
            Mount(
                "/ui",
                app=RequestGuard(
                    build_ui(service, settings),
                    settings,
                    repository,
                    required_scope="shadow_ai:read",
                ),
            )
        )
    routes.append(Mount("/", app=RequestGuard(mcp_app, settings, repository)))
    app = Starlette(routes=routes, lifespan=lifespan)
    return mcp, app, worker, service
