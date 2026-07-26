"""Prof nonce-based authentication for iframe embedding.

Provides:
- ProfAuthProvider: Extracts user identity from omnigent_session JWT cookie.
- ProfNonceMiddleware: Handles ?t={nonce} → validate → set cookie → redirect.
- create_prof_auth: Factory, returns (provider, middleware_cls, kwargs) or
  (None, None, None) when not configured.

Environment:
  OMNIGENT_BACKEND_URL         – prof-backend URL for nonce validation
  OMNIGENT_VM_ID               – this VM's ID (must match nonce binding)
  OMNIGENT_PROF_COOKIE_SECRET  – HS256 secret for session JWT (raw string)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx
import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from omnigent.server.auth import AuthProvider

logger = logging.getLogger(__name__)

COOKIE_NAME = "omnigent_session"
SESSION_TTL_SECONDS = 24 * 3600  # 24 hours

# Paths the middleware lets through without auth.
_PUBLIC_PREFIXES = ("/preview/", "/api/public/", "/health")


# ── Auth provider ───────────────────────────────────────────────────


class ProfAuthProvider(AuthProvider):
    """Extract user identity from the ``omnigent_session`` JWT cookie.

    One instance per process; constructed by :func:`create_prof_auth`.
    Thread-safe: only reads request cookies and an in-process JWT decode.
    """

    def __init__(self, cookie_secret: str):
        self._cookie_secret = cookie_secret.encode("utf-8")
        # Lightweight decode cache: hmac(token) → (user_id, expiry_monotonic).
        self._cache: dict[str, tuple[str, float]] = {}

    # ── AuthProvider interface ──────────────────────────────────

    def get_user_id(self, request: Request) -> str | None:
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            return None
        return self._validate_token(token)

    # ── internal ────────────────────────────────────────────────

    def _validate_token(self, token: str) -> str | None:
        import hmac as _hmac

        cache_key = _hmac.digest(
            token.encode(), self._cookie_secret, "sha256"
        ).hex()
        cached = self._cache.get(cache_key)
        now = time.monotonic()
        if cached is not None and cached[1] > now:
            return cached[0]

        try:
            payload: dict[str, Any] = jwt.decode(
                token, self._cookie_secret, algorithms=["HS256"]
            )
        except jwt.InvalidTokenError:
            return None

        user_id: str | None = payload.get("sub")
        if not user_id:
            return None

        exp: int = payload.get("exp", 0)
        remaining = exp - int(time.time())
        if remaining <= 0:
            return None

        # Cache for at most 5 minutes to bound staleness.
        self._cache[cache_key] = (user_id, now + min(remaining, 300))
        return user_id


# ── Nonce middleware ─────────────────────────────────────────────────


class ProfNonceMiddleware(BaseHTTPMiddleware):
    """Handle ``?t={nonce}`` → validate against backend → set cookie → redirect.

    Registered before all routes; intercepts the nonce query param before any
    handler sees it.  Public paths (preview, health) are passed through
    unmodified.
    """

    def __init__(
        self,
        app,
        backend_url: str,
        vm_id: str,
        cookie_secret: str,
    ):
        super().__init__(app)
        self._backend_url = backend_url.rstrip("/")
        self._vm_id = vm_id
        self._cookie_secret = cookie_secret.encode("utf-8")
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Public paths — no auth.
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Nonce exchange flow.
        nonce = request.query_params.get("t")
        if nonce:
            return await self._handle_nonce(request, nonce)

        return await call_next(request)

    async def _handle_nonce(self, request: Request, nonce: str) -> Response:
        url = f"{self._backend_url}/v1/cy/agentic/validate"
        try:
            resp = await self._http.post(
                url,
                json={"nonce": nonce, "vmID": self._vm_id},
            )
        except httpx.RequestError as exc:
            logger.warning("prof-auth: validate request failed: %s", exc)
            return Response("Authentication service unavailable", status_code=502)

        if resp.status_code != 200:
            logger.warning(
                "prof-auth: validate rejected status=%d body=%s",
                resp.status_code,
                resp.text[:200],
            )
            return Response("Invalid or expired authentication token", status_code=403)

        data = resp.json()
        user_id: str | None = data.get("userID")
        if not user_id:
            logger.warning("prof-auth: validate response missing userID")
            return Response("Invalid authentication response", status_code=502)

        # Mint session JWT.
        token = _mint_prof_token(user_id, self._cookie_secret)

        # Redirect to same URL without ?t= (strips nonce from browser history).
        redirect_url = str(request.url.remove_query_params("t"))
        response: Response = RedirectResponse(url=redirect_url, status_code=302)
        response.set_cookie(
            COOKIE_NAME,
            token,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        logger.info("prof-auth: nonce validated user=%s", user_id)
        return response


# ── Factory ──────────────────────────────────────────────────────────


def create_prof_auth() -> tuple[
    ProfAuthProvider | None,
    type[ProfNonceMiddleware] | None,
    dict[str, str] | None,
]:
    """Return (provider, middleware_class, middleware_kwargs) or all-None.

    All-None when any required env var is missing — the deployment has not
    opted into prof nonce auth.
    """
    backend_url = os.environ.get("OMNIGENT_BACKEND_URL", "")
    vm_id = os.environ.get("OMNIGENT_VM_ID", "")
    cookie_secret = os.environ.get("OMNIGENT_PROF_COOKIE_SECRET", "")

    if not backend_url or not vm_id or not cookie_secret:
        return None, None, None

    provider = ProfAuthProvider(cookie_secret=cookie_secret)
    kwargs: dict[str, str] = {
        "backend_url": backend_url,
        "vm_id": vm_id,
        "cookie_secret": cookie_secret,
    }
    return provider, ProfNonceMiddleware, kwargs


# ── helpers ──────────────────────────────────────────────────────────


def _mint_prof_token(user_id: str, cookie_secret: bytes) -> str:
    """Mint an HS256 JWT for the ``omnigent_session`` cookie."""
    now = int(time.time())
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
        "provider": "prof",
    }
    return jwt.encode(payload, cookie_secret, algorithm="HS256")
