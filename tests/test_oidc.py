import pytest
import jwt
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from sqlmodel import select
from app.main import app
from app.config import settings
from app.database import init_db, get_session
from app.models.user import User
from app.models.audit import AuditLog
from app.services.oidc_service import (
    get_redirect_uri,
    build_authorization_url,
    get_oidc_endpoints,
    _DISCOVERY_CACHE,
)


@pytest.fixture(autouse=True)
async def setup_oidc_test(monkeypatch):
    _DISCOVERY_CACHE.clear()
    monkeypatch.setattr(settings, "OIDC_ENABLED", True)
    monkeypatch.setattr(settings, "OIDC_ISSUER_URL", "https://auth.randomintervals.com")
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "dns-wui")
    monkeypatch.setattr(settings, "OIDC_CLIENT_SECRET", "test-secret-12345")
    monkeypatch.setattr(settings, "OIDC_REDIRECT_URI", "https://dns-wui.home.randomintervals.com/callback")
    await init_db()


@pytest.mark.asyncio
async def test_oidc_url_generation():
    state = "test_secure_state_123"
    auth_url, redirect_uri = await build_authorization_url(state=state)

    assert redirect_uri == "https://dns-wui.home.randomintervals.com/callback"
    assert "https://auth.randomintervals.com/oauth/authorize" in auth_url
    assert "client_id=dns-wui" in auth_url
    assert "state=test_secure_state_123" in auth_url
    assert "response_type=code" in auth_url


@pytest.mark.asyncio
async def test_oidc_login_disabled(monkeypatch):
    monkeypatch.setattr(settings, "OIDC_ENABLED", False)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
        res = await client.get("/login/oidc", follow_redirects=False)
        assert res.status_code == 307 or res.status_code == 302
        assert "/login" in res.headers["location"]
        assert "not+enabled" in res.headers["location"]


@pytest.mark.asyncio
async def test_oidc_login_redirect():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
        res = await client.get("/login/oidc", follow_redirects=False)
        assert res.status_code == 302
        assert "auth.randomintervals.com" in res.headers["location"]
        assert "client_id=dns-wui" in res.headers["location"]
        assert "oidc_state" in res.cookies


@pytest.mark.asyncio
async def test_oidc_callback_missing_code():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
        res = await client.get("/callback", follow_redirects=False)
        assert res.status_code == 307 or res.status_code == 302
        assert "/login" in res.headers["location"]
        assert "Missing+authorization+code" in res.headers["location"]


@pytest.mark.asyncio
async def test_oidc_callback_error_param():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
        res = await client.get(
            "/callback?error=access_denied&error_description=User+cancelled+authorization",
            follow_redirects=False,
        )
        assert res.status_code == 307 or res.status_code == 302
        assert "/login" in res.headers["location"]
        assert "User" in res.headers["location"]
        assert "cancelled" in res.headers["location"]


@pytest.mark.asyncio
async def test_oidc_callback_success_provision_user():
    secret_key = "a" * 32
    fake_tokens = {
        "access_token": "fake_at_xyz",
        "id_token": jwt.encode(
            {"sub": "pferland", "preferred_username": "pferland", "email": "pferland@home.local", "roles": ["admin"]},
            secret_key,
            algorithm="HS256",
        ),
    }
    fake_userinfo = {
        "sub": "user-uuid-123",
        "preferred_username": "pferland",
        "email": "pferland@randomintervals.com",
        "roles": ["admin"],
    }

    with patch("app.services.oidc_service.exchange_code_for_tokens", new=AsyncMock(return_value=fake_tokens)):
        with patch("app.services.oidc_service.fetch_user_info", new=AsyncMock(return_value=fake_userinfo)):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
                res = await client.get("/callback?code=mock_code_123&state=xyz", follow_redirects=False)
                assert res.status_code == 302
                assert res.headers["location"] == "/"
                assert "access_token" in res.cookies

                # Verify user was created in database
                from app.database import async_session_maker
                async with async_session_maker() as session:
                    res_user = await session.exec(select(User).where(User.username == "pferland"))
                    user = res_user.first()
                    assert user is not None
                    assert user.username == "pferland"
                    assert user.is_admin is True

                    # Verify audit log entry
                    res_audit = await session.exec(select(AuditLog).where(AuditLog.username == "pferland"))
                    audit = res_audit.first()
                    assert audit is not None
                    assert audit.action == "LOGIN_OIDC"


@pytest.mark.asyncio
async def test_oidc_bearer_token_authentication():
    mock_claims = {
        "sub": "user-uuid-999",
        "client_id": "android-homenet-hub",
        "preferred_username": "android_admin",
        "iss": "https://auth.randomintervals.com",
        "roles": ["admin"],
    }
    with patch("app.api.deps.verify_oidc_bearer_token", return_value=mock_claims):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="https://dns-wui.home.randomintervals.com") as client:
            res = await client.get("/api/v1/zones", headers={"Authorization": "Bearer mock-android-token-xyz"})
            assert res.status_code == 200

