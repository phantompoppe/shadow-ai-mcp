from __future__ import annotations

import argparse
import asyncio
import sys

from alembic import command
from alembic.config import Config
from pydantic import ValidationError

from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.server.app import build


def migrate(settings: Settings) -> None:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    command.upgrade(config, "head")


def main() -> None:
    parser = argparse.ArgumentParser(description="Shadow AI MCP")
    parser.add_argument("command", choices=["serve", "demo", "sync", "migrate"])
    args = parser.parse_args()
    try:
        settings = Settings()
        if args.command == "migrate":
            migrate(settings)
            return
        if args.command == "demo":
            if not settings.development_mode:
                raise ValueError("demo requires development mode")
            migrate(settings)
        mcp, app, worker, _ = build(settings)
        if args.command in {"demo", "sync"}:
            asyncio.run(worker.cycle())
            if args.command == "sync":
                return
            settings.run_worker = False
        if settings.transport == "stdio":
            mcp.run("stdio")
        else:
            import uvicorn

            uvicorn.run(app, host=settings.host, port=settings.port, log_config=None)
    except ValidationError as exc:
        fields = sorted({str(item["loc"][-1]) for item in exc.errors() if item["loc"]})
        print(
            f"Configuration validation failed in: {', '.join(fields) or 'settings'}",
            file=sys.stderr,
        )
        sys.exit(2)
    except (ValueError, OSError) as exc:
        safe_messages = (
            "JWT authentication requires",
            "JWKS URL must",
            "gateway mode requires",
            "gateway assertion secret",
            "pseudonymization key environment",
            "stdio is limited",
            "SQLite is allowed",
            "demo requires",
            "production HTTP connectors require HTTPS",
            "connector IDs must be unique",
        )
        message = str(exc) if str(exc).startswith(safe_messages) else type(exc).__name__
        print(f"Configuration error: {message}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(
            f"Startup failed: {type(exc).__name__}; check database and source configuration",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
