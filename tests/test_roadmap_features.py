import pytest
import io
import zipfile
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.database import init_db
from app.bind.discovery import append_zone_to_named_conf


@pytest.fixture(autouse=True)
async def setup_test_env(tmp_path, monkeypatch):
    test_zones_dir = tmp_path / "zones"
    test_named_conf = tmp_path / "named.conf"
    test_zones_dir.mkdir(parents=True)
    test_named_conf.write_text("", encoding="utf-8")

    monkeypatch.setattr(settings, "ZONES_DIR", test_zones_dir)
    monkeypatch.setattr(settings, "NAMED_CONF", test_named_conf)

    async def mock_reload(zone_name):
        return True, "Mock reload ok"
    async def mock_reconfig():
        return True, "Mock reconfig ok"
    async def mock_retransfer(zone_name):
        return True, "Mock retransfer ok"

    monkeypatch.setattr("app.bind.executor.reload_zone_rndc", mock_reload)
    monkeypatch.setattr("app.bind.executor.rndc_reconfig", mock_reconfig)
    monkeypatch.setattr("app.bind.executor.rndc_retransfer", mock_retransfer)
    monkeypatch.setattr("app.api.zones.reload_zone_rndc", mock_reload)
    monkeypatch.setattr("app.api.zones.rndc_reconfig", mock_reconfig)
    monkeypatch.setattr("app.api.zones.rndc_retransfer", mock_retransfer)

    await init_db()


@pytest.mark.asyncio
async def test_roadmap_features():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login as admin
        login_res = await client.post(
            "/api/v1/auth/login",
            json={"username": settings.ADMIN_USERNAME, "password": settings.ADMIN_PASSWORD},
        )
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. RNDC Operations
        flush_res = await client.post("/api/v1/system/rndc/flush", headers=headers)
        assert flush_res.status_code == 200

        flushname_res = await client.post(
            "/api/v1/system/rndc/flushname",
            headers=headers,
            json={"domain": "example.com"},
        )
        assert flushname_res.status_code == 200

        reconfig_res = await client.post("/api/v1/system/rndc/reconfig", headers=headers)
        assert reconfig_res.status_code == 200

        status_res = await client.get("/api/v1/system/rndc/status", headers=headers)
        assert status_res.status_code == 200

        # 3. Analytics Endpoint
        analytics_res = await client.get("/api/v1/system/analytics", headers=headers)
        assert analytics_res.status_code == 200
        assert "adblock_rules" in analytics_res.json()

        # 4. Dig Lookup Tool
        dig_res = await client.post(
            "/api/v1/tools/dig",
            headers=headers,
            json={"query": "localhost", "rtype": "A", "server": "127.0.0.1", "port": 53},
        )
        assert dig_res.status_code == 200
        assert "status" in dig_res.json()

        # 5. Create Master Zone
        create_res = await client.post(
            "/api/v1/zones",
            headers=headers,
            json={
                "origin": "mycorp.net.",
                "primary_ns": "ns1.mycorp.net.",
                "admin_email": "admin.mycorp.net.",
                "default_ttl": 3600,
                "create_named_conf_entry": True,
            },
        )
        assert create_res.status_code == 201

        # 6. Add Records & Verify Revision History
        add_rec = await client.post(
            "/api/v1/zones/mycorp.net/records",
            headers=headers,
            json={"name": "app", "rtype": "A", "ttl": 300, "rdata": "10.0.0.5", "sync_ptr": False},
        )
        assert add_rec.status_code == 201

        revs_res = await client.get("/api/v1/zones/mycorp.net/revisions", headers=headers)
        assert revs_res.status_code == 200
        revs = revs_res.json()
        assert len(revs) >= 2  # creation + record addition

        # 7. Revision Diff & Rollback
        first_rev_id = revs[-1]["id"]
        diff_res = await client.get(f"/api/v1/zones/mycorp.net/revisions/{first_rev_id}/diff", headers=headers)
        assert diff_res.status_code == 200
        assert "diff" in diff_res.json()

        rollback_res = await client.post(f"/api/v1/zones/mycorp.net/rollback/{first_rev_id}", headers=headers)
        assert rollback_res.status_code == 200
        assert "rolled back" in rollback_res.json()["message"]

        # 8. Pre-Flight Validation / Linting
        val_res = await client.post(
            "/api/v1/zones/mycorp.net/validate",
            headers=headers,
            json={"content": "$TTL 300\n@ IN SOA ns1.mycorp.net. admin.mycorp.net. 1 3600 600 86400 60\n@ IN NS ns1.mycorp.net.\napp IN CNAME target.com\napp IN A 1.2.3.4\n"},
        )
        assert val_res.status_code == 200
        val_data = val_res.json()
        # Should detect CNAME coexistence error
        assert any("CNAME" in i["message"] for i in val_data["issues"])

        # 9. Health Checker
        health_res = await client.get("/api/v1/zones/mycorp.net/health", headers=headers)
        assert health_res.status_code == 200
        health_data = health_res.json()
        assert "score" in health_data
        assert "status" in health_data

        # 10. Bulk TTL Update
        bulk_ttl_res = await client.post(
            "/api/v1/zones/mycorp.net/bulk-ttl",
            headers=headers,
            json={"ttl": 120},
        )
        assert bulk_ttl_res.status_code == 200

        # 11. Zone Export (BIND, JSON, CSV) & ZIP Archive
        exp_bind = await client.get("/api/v1/zones/mycorp.net/export?format=bind", headers=headers)
        assert exp_bind.status_code == 200
        assert "$TTL" in exp_bind.text

        exp_json = await client.get("/api/v1/zones/mycorp.net/export?format=json", headers=headers)
        assert exp_json.status_code == 200

        exp_csv = await client.get("/api/v1/zones/mycorp.net/export?format=csv", headers=headers)
        assert exp_csv.status_code == 200
        assert "name,type,ttl,data" in exp_csv.text

        exp_all = await client.get("/api/v1/zones/export/all", headers=headers)
        assert exp_all.status_code == 200
        # Check valid zip
        zip_obj = zipfile.ZipFile(io.BytesIO(exp_all.content))
        assert len(zip_obj.namelist()) > 0

        # 12. Secondary / Slave Zone Creation & Retransfer
        slave_res = await client.post(
            "/api/v1/zones/secondary",
            headers=headers,
            json={"origin": "mirroredcloud.org", "masters": ["198.51.100.10", "198.51.100.20"]},
        )
        assert slave_res.status_code == 201

        retransfer_res = await client.post("/api/v1/zones/mirroredcloud.org/retransfer", headers=headers)
        assert retransfer_res.status_code == 200

        # 13. API Key Creation & Usage via X-API-Key
        key_res = await client.post(
            "/api/v1/api-keys",
            headers=headers,
            json={"name": "ACME-Certbot", "role": "operator", "expires_in_days": 30},
        )
        assert key_res.status_code == 201
        key_data = key_res.json()
        secret_token = key_data["api_key"]
        key_id = key_data["id"]

        # Call with X-API-Key header
        api_headers = {"X-API-Key": secret_token}
        zones_via_key = await client.get("/api/v1/zones", headers=api_headers)
        assert zones_via_key.status_code == 200

        # Revoke Key
        revoke_res = await client.delete(f"/api/v1/api-keys/{key_id}", headers=headers)
        assert revoke_res.status_code == 200

        # Now X-API-Key should fail
        revoked_call = await client.get("/api/v1/zones", headers=api_headers)
        assert revoked_call.status_code == 401

        # 14. DDNS Token Creation & Update Endpoint
        ddns_create = await client.post(
            "/api/v1/ddns/tokens",
            headers=headers,
            json={"name": "HomeRouter", "zone_name": "mycorp.net", "record_name": "wan"},
        )
        assert ddns_create.status_code == 201
        token_secret = ddns_create.json()["token"]
        token_id = ddns_create.json()["id"]


        # Call DDNS update
        ddns_update = await client.get(f"/api/v1/ddns/update?token={token_secret}&myip=203.0.113.88")
        assert ddns_update.status_code == 200
        assert "good 203.0.113.88" in ddns_update.text

        # 15. Backup Snapshot Creation, Listing, and Restoration
        backup_create = await client.post("/api/v1/backups", headers=headers, json={"comment": "Test snapshot"})
        assert backup_create.status_code == 200
        backup_fn = backup_create.json()["filename"]

        backup_list = await client.get("/api/v1/backups", headers=headers)
        assert backup_list.status_code == 200
        assert any(b["filename"] == backup_fn for b in backup_list.json()["backups"])

        backup_restore = await client.post("/api/v1/backups/restore", headers=headers, json={"filename": backup_fn})
        assert backup_restore.status_code == 200

        # 16. DNSSEC endpoint inspection
        dnssec_res = await client.get("/api/v1/zones/mycorp.net/dnssec", headers=headers)
        assert dnssec_res.status_code == 200
        assert "signed" in dnssec_res.json()

        # 17. HTML pages render cleanly
        tools_html = await client.get("/tools", headers=headers)
        assert tools_html.status_code == 200
        assert "DNS Diagnostics & Tools" in tools_html.text

        keys_html = await client.get("/api-keys", headers=headers)
        assert keys_html.status_code == 200
        assert "API Keys & Automation Tokens" in keys_html.text

