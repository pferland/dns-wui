import json
from typing import Any
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.models.setting import AppSetting

CONFIGURABLE_FIELDS = {
    "APP_NAME": {"type": "str", "category": "General", "description": "Display name of the application"},
    "SERVER_HOST": {"type": "str", "category": "Server", "description": "Server listening host address"},
    "SERVER_PORT": {"type": "int", "category": "Server", "description": "Server listening port"},
    "BASE_URL": {"type": "str", "category": "Server", "description": "External Base URL for callbacks/DDNS"},
    "NAMED_CONF": {"type": "path", "category": "BIND 9 Paths", "description": "Path to primary named.conf"},
    "ZONES_DIR": {"type": "path", "category": "BIND 9 Paths", "description": "Root directory containing zone files"},
    "CHECKZONE_BIN": {"type": "str", "category": "Binaries", "description": "named-checkzone binary path"},
    "CHECKCONF_BIN": {"type": "str", "category": "Binaries", "description": "named-checkconf binary path"},
    "RNDC_BIN": {"type": "str", "category": "Binaries", "description": "rndc control binary path"},
    "USE_SUDO_FOR_RNDC": {"type": "bool", "category": "Binaries", "description": "Prepend sudo to rndc executions"},
    "DEFAULT_SOA_STRATEGY": {"type": "choice", "choices": ["date_revision", "increment"], "category": "DNS Operations", "description": "SOA serial generation strategy"},
    "AUTO_PTR_SYNC": {"type": "bool", "category": "DNS Operations", "description": "Auto-create and sync reverse PTR records on A/AAAA edits"},
    "OVERRIDE_ZONE_NAME": {"type": "str", "category": "DNS Operations", "description": "Zone name for split-horizon RPZ overrides"},
    "IGNORED_ZONES": {"type": "list", "category": "DNS Operations", "description": "Ignored/hidden zones (comma-separated or JSON list)"},
    "AUTH_MODE": {"type": "choice", "choices": ["local", "hybrid", "none"], "category": "Security & Auth", "description": "Authentication mode"},
    "JWT_EXPIRATION_HOURS": {"type": "int", "category": "Security & Auth", "description": "JWT session token lifespan in hours"},
    "TOTP_ENABLED": {"type": "bool", "category": "Security & Auth", "description": "Enable two-factor authentication (TOTP)"},
    "TOTP_ISSUER": {"type": "str", "category": "Security & Auth", "description": "Issuer name displayed in authenticator apps"},
    "OIDC_ENABLED": {"type": "bool", "category": "Single Sign-On (OIDC)", "description": "Enable OpenID Connect SSO"},
    "OIDC_ISSUER_URL": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Provider Issuer Discovery URL"},
    "OIDC_CLIENT_ID": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Client ID"},
    "OIDC_CLIENT_SECRET": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Client Secret (Stored securely)"},
    "OIDC_REDIRECT_URI": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC OAuth2 Redirect URI Callback"},
}


async def load_settings_from_db(session: AsyncSession) -> None:
    """Load persistent settings overrides from DB into runtime settings object."""
    result = await session.exec(select(AppSetting))
    db_settings = result.all()
    for row in db_settings:
        if row.key in CONFIGURABLE_FIELDS:
            meta = CONFIGURABLE_FIELDS[row.key]
            val = parse_setting_value(row.value, meta["type"])
            settings.apply_override(row.key, val)


def parse_setting_value(val_str: str, val_type: str) -> Any:
    """Parse string value from DB/form into typed python value."""
    if val_type == "bool":
        if isinstance(val_str, bool):
            return val_str
        return str(val_str).lower() in ("true", "1", "yes", "on")
    elif val_type == "int":
        try:
            return int(val_str)
        except (ValueError, TypeError):
            return 0
    elif val_type == "list":
        if isinstance(val_str, list):
            return val_str
        val_str = str(val_str).strip()
        if val_str.startswith("["):
            try:
                parsed = json.loads(val_str)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                pass
        return [x.strip() for x in val_str.replace("\n", ",").split(",") if x.strip()]
    elif val_type == "path":
        return str(val_str).strip()
    return str(val_str).strip() if val_str is not None else ""


async def save_settings_to_db(session: AsyncSession, new_settings: dict[str, Any]) -> dict[str, Any]:
    """Persist settings to DB and update runtime config."""
    updated = {}
    for key, raw_val in new_settings.items():
        if key not in CONFIGURABLE_FIELDS:
            continue
        meta = CONFIGURABLE_FIELDS[key]
        parsed_val = parse_setting_value(raw_val, meta["type"])

        # Serialize for DB storage
        if meta["type"] == "list":
            stored_str = json.dumps(parsed_val)
        elif meta["type"] == "bool":
            stored_str = "true" if parsed_val else "false"
        else:
            stored_str = str(parsed_val) if parsed_val is not None else ""

        # Query or update row
        result = await session.exec(select(AppSetting).where(AppSetting.key == key))
        existing = result.first()
        if existing:
            existing.value = stored_str
            session.add(existing)
        else:
            new_row = AppSetting(key=key, value=stored_str)
            session.add(new_row)

        settings.apply_override(key, parsed_val)
        updated[key] = parsed_val

    await session.commit()
    return updated


async def get_all_settings_view(session: AsyncSession) -> list[dict[str, Any]]:
    """Return all settings with metadata, current runtime value, and category."""
    # Ensure runtime has latest from DB
    await load_settings_from_db(session)

    res = []
    for key, meta in CONFIGURABLE_FIELDS.items():
        curr_val = getattr(settings, key, None)
        # Convert Path to str for display
        if hasattr(curr_val, "as_posix"):
            curr_val = str(curr_val)

        res.append({
            "key": key,
            "category": meta["category"],
            "type": meta["type"],
            "description": meta["description"],
            "choices": meta.get("choices"),
            "value": curr_val,
        })
    return res
