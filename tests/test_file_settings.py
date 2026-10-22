import os
import tempfile
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport
from app.config import Settings, get_config_file_path
from app.services.settings_service import (
    save_settings_to_file,
    apply_saved_settings,
    get_all_settings_view,
    read_file_settings,
)
from app.main import app
from app.database import init_db, engine
from sqlalchemy import text


@pytest.mark.asyncio
async def test_env_file_settings_lifecycle(tmp_path: Path, monkeypatch):
    """Verify settings can be loaded, edited on disk, saved, and reloaded via .env."""
    test_env = tmp_path / ".env"
    test_env.write_text("APP_NAME=Disk BIND Manager\nSERVER_PORT=9100\nOIDC_ENABLED=true\n")

    monkeypatch.setenv("ENV_FILE", str(test_env))

    # 1. Instantiation loads directly from .env
    test_settings = Settings(_env_file=str(test_env))
    assert test_settings.APP_NAME == "Disk BIND Manager"
    assert test_settings.SERVER_PORT == 9100
    assert test_settings.OIDC_ENABLED is True

    # 2. Saving to file updates .env
    saved = await save_settings_to_file({
        "APP_NAME": "Updated Via File Save",
        "SERVER_PORT": 9200,
        "OIDC_ENABLED": False,
    })
    assert saved["APP_NAME"] == "Updated Via File Save"
    assert saved["SERVER_PORT"] == 9200
    assert saved["OIDC_ENABLED"] is False

    # Read raw file to verify update persisted to disk
    raw_content = test_env.read_text()
    assert "Updated Via File Save" in raw_content
    assert "9200" in raw_content
    assert "false" in raw_content

    # 3. Reload from file applies to runtime
    applied = await apply_saved_settings()
    assert applied["APP_NAME"] == "Updated Via File Save"
    assert applied["SERVER_PORT"] == 9200
    assert applied["OIDC_ENABLED"] is False


@pytest.mark.asyncio
async def test_ini_file_settings_support(tmp_path: Path, monkeypatch):
    """Verify settings can be loaded from config.ini."""
    test_ini = tmp_path / "config.ini"
    test_ini.write_text(
        "[dns_wui]\n"
        "app_name = INI BIND Manager\n"
        "server_port = 8888\n"
        "oidc_enabled = true\n"
    )

    monkeypatch.setenv("DNS_WUI_CONFIG_FILE", str(test_ini))

    test_settings = Settings()
    assert test_settings.APP_NAME == "INI BIND Manager"
    assert test_settings.SERVER_PORT == 8888
    assert test_settings.OIDC_ENABLED is True

    file_data = read_file_settings()
    assert file_data["APP_NAME"] == "INI BIND Manager"
    assert file_data["SERVER_PORT"] == "8888"


@pytest.mark.asyncio
async def test_no_app_settings_table_in_db():
    """Verify SQLite database does not store settings."""
    await init_db()
    async with engine.begin() as conn:
        res = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='app_settings'")
        )
        assert res.first() is None, "app_settings table must not exist in SQLite DB"
