from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from shadow_ai_mcp.auth.core import Authenticator, SecurityError
from shadow_ai_mcp.config.settings import Settings


def test_jwt_issuer_audience_signature_and_scope(tmp_path: object) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    settings = Settings(
        auth_mode="jwt",
        jwt_issuer="https://issuer.example/",
        jwt_audience="shadow-ai",
        jwt_jwks_url="https://issuer.example/jwks",
    )
    auth = Authenticator(settings)
    auth.jwks = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=private.public_key())
    )
    claims = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": "analyst",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
        "scope": "shadow_ai:read shadow_ai:evidence:read",
    }
    token = jwt.encode(claims, private, algorithm="RS256")
    principal = auth.authenticate({"authorization": "Bearer " + token}, "203.0.113.1")
    assert principal.identity == "analyst" and "shadow_ai:read" in principal.scopes
    claims["aud"] = "different-service"
    invalid = jwt.encode(claims, private, algorithm="RS256")
    with pytest.raises(SecurityError):
        auth.authenticate({"authorization": "Bearer " + invalid}, "203.0.113.1")


def test_gateway_attestation_and_peer_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHADOW_GATEWAY_SECRET", "local-test-only")
    settings = Settings(
        auth_mode="gateway",
        gateway_trusted_cidrs=["10.20.0.0/16"],
        gateway_assertion_secret_env="SHADOW_GATEWAY_SECRET",
    )
    auth = Authenticator(settings)
    identity, scopes, timestamp = "security-analyst", "shadow_ai:read", str(int(time.time()))
    signature = hmac.new(
        b"local-test-only", f"{identity}|{scopes}|{timestamp}".encode(), hashlib.sha256
    ).hexdigest()
    headers = {
        "x-shadow-identity": identity,
        "x-shadow-scopes": scopes,
        "x-shadow-timestamp": timestamp,
        "x-shadow-assertion": signature,
    }
    assert auth.authenticate(headers, "10.20.1.2").identity == identity
    with pytest.raises(SecurityError):
        auth.authenticate(headers, "10.21.1.2")
    with pytest.raises(SecurityError):
        auth.authenticate({**headers, "x-shadow-scopes": "shadow_ai:admin"}, "10.20.1.2")
    with pytest.raises(SecurityError):
        auth.authenticate(
            {**headers, "x-shadow-timestamp": str(int(time.time()) - 300)}, "10.20.1.2"
        )
