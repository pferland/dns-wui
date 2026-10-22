import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.database import init_db
from app.services.security import hash_password, verify_password


def test_password_argon2():
    pwd = "super-secret-password-123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrong-password", hashed) is False


@pytest.mark.asyncio
async def test_direct_login_no_mfa():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/auth/login",
            json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["access_token"] is not None
        assert data["requires_2fa"] is False
        assert "access_token" in res.cookies
