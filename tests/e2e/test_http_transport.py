from __future__ import annotations

import asyncio
import socket

import httpx
import pytest
import uvicorn
from mcp.client import Client

from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.server.app import build


@pytest.mark.asyncio
async def test_streamable_http_live_service(
    environment: tuple[Settings, object, object, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings, _, worker, _ = environment
    await worker.cycle()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    settings.allowed_hosts = [f"127.0.0.1:{port}"]
    _, app, _, _ = build(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None, lifespan="on")
    )
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        assert server.started
        for key in (
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
        ):
            monkeypatch.delenv(key, raising=False)
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.post(f"http://127.0.0.1:{port}/mcp", json={})
            # Dev identity is limited to loopback; the local client is allowed here.
            assert response.status_code != 401
        async with Client(f"http://127.0.0.1:{port}/mcp") as client:
            result = await client.call_tool("search_shadow_ai", {"limit": 2})
            assert not result.is_error
            assert len(result.structured_content["findings"]) == 2
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
