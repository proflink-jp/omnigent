"""Unit tests for ProfNonceMiddleware (iframe gate + internal client bypass)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from omnigent.runner.identity import OMNIGENT_INTERNAL_WS_ORIGIN
from omnigent.server.prof_auth import ProfNonceMiddleware


async def _ok(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def _app() -> Starlette:
    starlette = Starlette(routes=[Route("/{path:path}", _ok, methods=["GET", "POST"])])
    return ProfNonceMiddleware(
        starlette,
        backend_url="https://api.example.test",
        vm_id="01TESTVM",
        frame_parent="https://cy.prof.link",
    )


@pytest.mark.asyncio
async def test_bare_request_without_session_is_unauthorized() -> None:
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/v1/sessions")
    assert resp.status_code == 401
    assert resp.text == "Unauthorized"


@pytest.mark.asyncio
async def test_health_is_public() -> None:
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "ok"


@pytest.mark.asyncio
async def test_internal_origin_bypasses_cookie_gate() -> None:
    """Runner/host mint + agent-spec HTTP use Origin: omnigent://internal."""
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/runners/runner_token_abc/token",
            headers={"Origin": OMNIGENT_INTERNAL_WS_ORIGIN},
        )
        assert resp.status_code == 200
        assert resp.text == "ok"

        resp = await client.get(
            "/v1/sessions/conv_x/agent/contents",
            headers={"Origin": OMNIGENT_INTERNAL_WS_ORIGIN},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_foreign_origin_without_session_is_unauthorized() -> None:
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/v1/sessions",
            headers={"Origin": "https://evil.example"},
        )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_prof_middleware_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from omnigent.server.prof_auth import create_prof_middleware

    monkeypatch.delenv("OMNIGENT_BACKEND_URL", raising=False)
    monkeypatch.delenv("OMNIGENT_VM_ID", raising=False)
    assert create_prof_middleware() == (None, None)

    monkeypatch.setenv("OMNIGENT_BACKEND_URL", "https://api.example")
    monkeypatch.setenv("OMNIGENT_VM_ID", "01X")
    cls, kwargs = create_prof_middleware()
    assert cls is ProfNonceMiddleware
    assert kwargs is not None
    assert kwargs["backend_url"] == "https://api.example"
    assert kwargs["vm_id"] == "01X"
