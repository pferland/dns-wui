import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.database import init_db


@pytest.mark.asyncio
async def test_full_zone_lifecycle(tmp_path, monkeypatch):
    test_zones_dir = tmp_path / "zones"
    test_named_conf = tmp_path / "named.conf.local"
    test_zones_dir.mkdir(parents=True)
    test_named_conf.write_text("", encoding="utf-8")

    monkeypatch.setattr(settings, "ZONES_DIR", test_zones_dir)
    monkeypatch.setattr(settings, "NAMED_CONF", test_named_conf)

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

        # 2. Create Forward Zone
        create_res = await client.post(
            "/api/v1/zones",
            headers=headers,
            json={
                "origin": "homelab.net.",
                "primary_ns": "ns1.homelab.net.",
                "admin_email": "admin.homelab.net.",
                "default_ttl": 3600,
                "create_named_conf_entry": True,
            },
        )
        assert create_res.status_code == 201
        zone_info = create_res.json()
        assert zone_info["name"] == "homelab.net."

        # 3. Create Reverse Zone
        rev_create_res = await client.post(
            "/api/v1/zones",
            headers=headers,
            json={
                "origin": "1.168.192.in-addr.arpa.",
                "primary_ns": "ns1.homelab.net.",
                "admin_email": "admin.homelab.net.",
                "default_ttl": 3600,
                "create_named_conf_entry": True,
            },
        )
        assert rev_create_res.status_code == 201

        # 4. Add A record with sync_ptr: True
        add_rec_res = await client.post(
            "/api/v1/zones/homelab.net/records",
            headers=headers,
            json={
                "name": "server",
                "rtype": "A",
                "ttl": 3600,
                "rdata": "192.168.1.150",
                "sync_ptr": True,
            },
        )
        assert add_rec_res.status_code == 201
        rec_data = add_rec_res.json()
        assert "ptr_sync" in rec_data
        assert "PTR in 1.168.192.in-addr.arpa" in rec_data["ptr_sync"]

        # 5. Verify reverse zone contains the synced PTR record
        rev_zone_res = await client.get("/api/v1/zones/1.168.192.in-addr.arpa", headers=headers)
        assert rev_zone_res.status_code == 200
        rev_records = rev_zone_res.json()["records"]
        ptr_records = [r for r in rev_records if r["rtype"] == "PTR"]
        assert len(ptr_records) == 1
        assert ptr_records[0]["name"] == "150"
        assert ptr_records[0]["rdata"] == "server.homelab.net."

        # 6. Delete A record with sync_ptr: True
        del_res = await client.request(
            method="DELETE",
            url="/api/v1/zones/homelab.net/records",
            headers=headers,
            json={
                "name": "server",
                "rtype": "A",
                "rdata": "192.168.1.150",
                "sync_ptr": True,
            },
        )
        assert del_res.status_code == 200

        # Verify PTR was cleaned up
        rev_zone_res2 = await client.get("/api/v1/zones/1.168.192.in-addr.arpa", headers=headers)
        rev_records2 = rev_zone_res2.json()["records"]
        ptr_records2 = [r for r in rev_records2 if r["rtype"] == "PTR"]
        assert len(ptr_records2) == 0

        # 7. Check Audit Logs
        audit_res = await client.get("/api/v1/audit", headers=headers)
        assert audit_res.status_code == 200
        logs = audit_res.json()
        assert len(logs) >= 3
