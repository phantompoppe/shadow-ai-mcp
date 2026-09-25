from __future__ import annotations

from pathlib import Path

import pytest

from shadow_ai_mcp.cli import migrate
from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.server.app import build


@pytest.fixture
def project_root(monkeypatch: pytest.MonkeyPatch) -> Path:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def environment(project_root: Path, tmp_path: Path) -> tuple[Settings, object, object, object]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'shadow.sqlite'}",
        auth_mode="dev",
        development_mode=True,
        run_worker=False,
        metadata_allowlist=["environment"],
    )
    migrate(settings)
    mcp, app, worker, service = build(settings)
    return settings, mcp, worker, service
