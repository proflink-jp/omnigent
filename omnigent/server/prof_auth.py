"""Prof agent iframe auth gate.

Rules (docs/dev-env.md Auth):

1. Direct browser hit → 401 (no bare URL access).
2. Iframe only; parent origin must be production prof-cy (`https://cy.prof.link`).
3. Nonce validates a one-shot session; after success a cookie keeps the iframe alive.

First-party non-browser clients (host + runner) set
``Origin: omnigent://internal`` (see :data:`OMNIGENT_INTERNAL_WS_ORIGIN`).
Those requests skip the iframe/cookie gate so runner HTTP callbacks
(``POST /v1/runners/{id}/token``, ``GET /v1/sessions/.../agent/contents``,
tool_dispatch) can reach the app. Browsers cannot set that Origin.
Downstream routes still enforce their own auth (binding token, session
auth provider, or open single-user when ``OMNIGENT_AUTH_ENABLED=0``).

Environment:
  OMNIGENT_BACKEND_URL  – prod API for nonce validation (required)
  OMNIGENT_VM_ID        – this env's ULID, must match nonce binding (required)
  OMNIGENT_FRAME_PARENT – allowed embed parent origin (default https://cy.prof.link)

No-op when OMNIGENT_BACKEND_URL or OMNIGENT_VM_ID is unset.
"""

from __future__ import annotations

import logging
import os
import secrets
from urllib.parse import urlparse

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from omnigent.runner.identity import OMNIGENT_INTERNAL_WS_ORIGIN

logger = logging.getLogger(__name__)

_PUBLIC_PREFIXES = ("/preview/", "/api/public/", "/health")
_SESSION_COOKIE = "prof_agent_session"
_DEFAULT_FRAME_PARENT = "https://cy.prof.link"


class ProfNonceMiddleware(BaseHTTPMiddleware):
    """Gate agent origin: frame parent + nonce → session cookie."""

    def __init__(
        self,
        app,
        backend_url: str,
        vm_id: str,
        frame_parent: str = _DEFAULT_FRAME_PARENT,
    ):
        super().__init__(app)
        self._backend_url = backend_url.rstrip("/")
        self._vm_id = vm_id
        self._frame_parent = frame_parent.rstrip("/")
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        # Single-process VM; restart drops sessions (re-open from cy).
        self._sessions: set[str] = set()

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Host/runner HTTP (mint token, agent bundle, tool callbacks).
        # Must not require the browser session cookie — see module docstring.
        if self._is_internal_client(request):
            return await call_next(request)

        nonce = request.query_params.get("t")
        if nonce:
            return await self._handle_nonce(request, nonce)

        if not self._has_session(request):
            return Response("Unauthorized", status_code=401)

        # Top-level tab navigation with a leftover cookie still denied.
        if self._is_top_level_document(request):
            return Response("Unauthorized", status_code=401)

        return await call_next(request)

    @staticmethod
    def _is_internal_client(request: Request) -> bool:
        """True when the request is from an Omnigent host/runner process.

        :param request: Incoming ASGI request.
        :returns: Whether ``Origin`` is the first-party sentinel.
        """
        return request.headers.get("origin", "") == OMNIGENT_INTERNAL_WS_ORIGIN

    def _has_session(self, request: Request) -> bool:
        token = request.cookies.get(_SESSION_COOKIE, "")
        return bool(token) and token in self._sessions

    def _is_framed_by_parent(self, request: Request) -> bool:
        """True when the browser indicates iframe under the allowed parent."""
        dest = request.headers.get("sec-fetch-dest", "").lower()
        if dest == "iframe":
            # Prefer Referer when present; some browsers omit it under strict policy.
            referer = request.headers.get("referer", "")
            if not referer:
                return True
            return self._referer_is_parent(referer)

        referer = request.headers.get("referer", "")
        if referer and self._referer_is_parent(referer):
            return True
        return False

    def _referer_is_parent(self, referer: str) -> bool:
        try:
            parsed = urlparse(referer)
        except ValueError:
            return False
        origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        return origin == self._frame_parent

    @staticmethod
    def _is_top_level_document(request: Request) -> bool:
        """Sec-Fetch-Dest: document = top-level navigation (new tab / address bar)."""
        return request.headers.get("sec-fetch-dest", "").lower() == "document"

    async def _handle_nonce(self, request: Request, nonce: str) -> Response:
        if not self._is_framed_by_parent(request):
            logger.warning("prof-auth: nonce request not framed by %s", self._frame_parent)
            return Response("Unauthorized", status_code=401)

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
            return Response("Unauthorized", status_code=401)

        session = secrets.token_urlsafe(32)
        self._sessions.add(session)
        logger.info("prof-auth: validated ok  vm=%s", self._vm_id)

        # Strip ?t= so the nonce never stays in history / address bar.
        # cloudflared terminates TLS → request.url is http; restore scheme.
        redirect_url = request.url.remove_query_params("t")
        proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        if proto:
            redirect_url = redirect_url.replace(scheme=proto)

        response = RedirectResponse(url=str(redirect_url), status_code=302)
        response.set_cookie(
            key=_SESSION_COOKIE,
            value=session,
            httponly=True,
            secure=True,
            samesite="none",
            path="/",
            max_age=12 * 60 * 60,
        )
        return response


def create_prof_middleware() -> tuple[
    type[ProfNonceMiddleware] | None,
    dict[str, str] | None,
]:
    """Return (middleware_class, middleware_kwargs) or (None, None).

    None when OMNIGENT_BACKEND_URL or OMNIGENT_VM_ID is unset.
    """
    backend_url = os.environ.get("OMNIGENT_BACKEND_URL", "")
    vm_id = os.environ.get("OMNIGENT_VM_ID", "")
    frame_parent = os.environ.get("OMNIGENT_FRAME_PARENT", _DEFAULT_FRAME_PARENT)

    if not backend_url or not vm_id:
        return None, None

    return ProfNonceMiddleware, {
        "backend_url": backend_url,
        "vm_id": vm_id,
        "frame_parent": frame_parent,
    }
