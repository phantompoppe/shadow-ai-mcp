from __future__ import annotations

import contextvars

correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "shadow_correlation_id", default=None
)
