from __future__ import annotations

import contextvars
import hashlib
import hmac
import ipaddress
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass

import jwt
from jwt import PyJWKClient

from shadow_ai_mcp.config.settings import Settings
from shadow_ai_mcp.observability.metrics import AUTH_FAILURES


class SecurityError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Principal:
    identity: str
    scopes: frozenset[str]


current_principal: contextvars.ContextVar[Principal | None] = contextvars.ContextVar(
    "shadow_principal", default=None
)


def require(scope: str) -> Principal:
    principal = current_principal.get()
    if principal is None:
        AUTH_FAILURES.labels("unauthenticated").inc()
        raise SecurityError("UNAUTHENTICATED")
    if scope not in principal.scopes and "shadow_ai:admin" not in principal.scopes:
        AUTH_FAILURES.labels("forbidden").inc()
        raise SecurityError("FORBIDDEN")
    return principal


class Authenticator:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.jwks = (
            PyJWKClient(settings.jwt_jwks_url, cache_keys=True, lifespan=300)
            if (settings.auth_mode == "jwt" and settings.jwt_jwks_url)
            else None
        )

    def authenticate(self, headers: Mapping[str, str], peer_ip: str | None) -> Principal:
        if self.settings.auth_mode == "dev":
            if (
                not self.settings.development_mode
                or not peer_ip
                or not any(
                    ipaddress.ip_address(peer_ip) in ipaddress.ip_network(cidr)
                    for cidr in self.settings.dev_trusted_cidrs
                )
            ):
                raise SecurityError("UNAUTHENTICATED")
            return Principal(
                "local-developer", frozenset({"shadow_ai:read", "shadow_ai:evidence:read"})
            )
        if self.settings.auth_mode == "gateway":
            try:
                if not peer_ip or not any(
                    ipaddress.ip_address(peer_ip) in ipaddress.ip_network(cidr)
                    for cidr in self.settings.gateway_trusted_cidrs
                ):
                    raise SecurityError("UNAUTHENTICATED")
                identity = headers.get(self.settings.gateway_identity_header, "")
                scopes = headers.get(self.settings.gateway_scopes_header, "")
                timestamp = headers.get("x-shadow-timestamp", "")
                assertion = headers.get(self.settings.gateway_assertion_header, "")
                secret = os.getenv(self.settings.gateway_assertion_secret_env or "")
                if not secret or not identity or len(identity) > 256 or len(scopes) > 512:
                    raise SecurityError("UNAUTHENTICATED")
                if abs(time.time() - int(timestamp)) > 60:
                    raise SecurityError("UNAUTHENTICATED")
                expected = hmac.new(
                    secret.encode(), f"{identity}|{scopes}|{timestamp}".encode(), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(assertion, expected):
                    raise SecurityError("UNAUTHENTICATED")
                return Principal(identity, frozenset(scopes.split()))
            except (ValueError, TypeError) as exc:
                raise SecurityError("UNAUTHENTICATED") from exc
        token = headers.get("authorization", "")
        if not token.startswith("Bearer ") or self.jwks is None:
            raise SecurityError("UNAUTHENTICATED")
        try:
            raw = token.removeprefix("Bearer ")
            key = self.jwks.get_signing_key_from_jwt(raw).key
            claims = jwt.decode(
                raw,
                key,
                algorithms=["RS256", "ES256"],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            scopes = claims.get("scope", "")
            if not isinstance(scopes, str):
                raise SecurityError("UNAUTHENTICATED")
            return Principal(str(claims["sub"]), frozenset(scopes.split()))
        except (jwt.PyJWTError, ValueError) as exc:
            raise SecurityError("UNAUTHENTICATED") from exc
