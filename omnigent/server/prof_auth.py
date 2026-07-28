"""Prof nonce gate for iframe embedding.

A single Starlette middleware that intercepts ``?t={nonce}`` on the first
request, validates it against the prof backend, and redirects to strip the
query param.  All subsequent requests pass through untouched — omnigent runs
with no auth at all.  The nonce is purely a one-time door: if you don't have
a valid nonce, you can't reach omnigent through the iframe.

Environment:
  OMNIGENT_BACKEND_URL  – prof-backend URL for nonce validation (required)
  OMNIGENT_VM_ID        – this VM's ID, must match the nonce binding (required)

No-op when either env var is unset.
"""

from __future__ import annotations

import logging
import os

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)

# Paths the middleware passes through without nonce checking.
_PUBLIC_PREFIXES = ("/preview/", "/api/public/", "/health")

# ── Middleware ────────────────────────────────────────────────────────


class ProfNonceMiddleware(BaseHTTPMiddleware):
    """Validate ``?t={nonce}`` once, then get out of the way."""

    def __init__(self, app, backend_url: str, vm_id: str):
        super().__init__(app)
        self._backend_url = backend_url.rstrip("/")
        self._vm_id = vm_id
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0))

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Public paths — no gate.
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Nonce gate.
        nonce = request.query_params.get("t")
        if nonce:
            return await self._handle_nonce(request, nonce)

        # No nonce, no gate — omnigent runs open.
        return await call_next(request)

    async def _handle_nonce(self, request: Request, nonce: str) -> Response:
        url = f"{self._backend_url}/v1/cy/agentic/validate"
        try:
            resp = await self._http.post(
                url,
                json={"nonce": nonce, "vmID": self._vm_id},
            )
        except httpx.RequestError as exc:
            logger.warning("prof-nonce: validate request failed: %s", exc)
            return Response("Authentication service unavailable", status_code=502)

        if resp.status_code != 200:
            logger.warning(
                "prof-nonce: validate rejected status=%d body=%s",
                resp.status_code,
                resp.text[:200],
            )
            return Response("Invalid or expired authentication token", status_code=403)

        logger.info("prof-nonce: validated ok  vm=%s", self._vm_id)

        # Redirect to same URL without ?t= (strips nonce from history).
        # Cloudflare terminates TLS and cloudflared forwards to
        # http://localhost:8080, so request.url carries the http scheme.
        # Redirecting an https-embedded iframe to http is blocked as mixed
        # content, leaving the frame blank.
        redirect_url = request.url.remove_query_params("t")
        proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        if proto:
            redirect_url = redirect_url.replace(scheme=proto)
        return RedirectResponse(url=str(redirect_url), status_code=302)


# ── Factory ───────────────────────────────────────────────────────────


def create_prof_middleware() -> tuple[
    type[ProfNonceMiddleware] | None,
    dict[str, str] | None,
]:
    """Return (middleware_class, middleware_kwargs) or (None, None).

    None when OMNIGENT_BACKEND_URL or OMNIGENT_VM_ID is unset.
    """
    backend_url = os.environ.get("OMNIGENT_BACKEND_URL", "")
    vm_id = os.environ.get("OMNIGENT_VM_ID", "")

    if not backend_url or not vm_id:
        return None, None

    return ProfNonceMiddleware, {"backend_url": backend_url, "vm_id": vm_id}
