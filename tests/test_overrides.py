import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.database import init_db


@pytest.mark.asyncio
async def test_overrides_lifecycle(tmp_path, monkeypatch):
    test_zones_dir = tmp_path / "zones"
    test_zones_dir.mkdir(parents=True)
    test_override_file = test_zones_dir / "rpz.overrides.local"

    monkeypatch.setattr(settings, "ZONES_DIR", test_zones_dir)
    monkeypatch.setattr(settings, "OVERRIDE_ZONE_FILE", test_override_file)
    # Mock reload_zone_rndc to avoid running rndc in tests
    async def mock_reload(zone_name):
        return True, "Zone reloaded"
    monkeypatch.setattr("app.bind.executor.reload_zone_rndc", mock_reload)

    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Get Overrides initially (empty)
        res = await client.get("/api/v1/overrides", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

        # 3. Add an override
        add_res = await client.post(
            "/api/v1/overrides",
            headers=headers,
            json={
                "fqdn": "nas.example.com",
                "target": "192.168.1.100",
                "record_type": "A",
                "ttl": 300,
            },
        )
        assert add_res.status_code == 200
        assert "nas.example.com" in add_res.json()["message"]

        # 4. Verify listed
        res = await client.get("/api/v1/overrides", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 1
        assert data[0]["fqdn"] == "nas.example.com"
        assert data[0]["target"] == "192.168.1.100"
        assert data[0]["record_type"] == "A"

        # 5. Delete override
        del_res = await client.delete("/api/v1/overrides/nas.example.com", headers=headers)
        assert del_res.status_code == 200

        # 6. Verify empty again
        res = await client.get("/api/v1/overrides", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 0

        # 7. Test HTML page
        html_res = await client.get("/overrides", headers=headers)
        assert html_res.status_code == 200
        assert "Local DNS Overrides" in html_res.text
