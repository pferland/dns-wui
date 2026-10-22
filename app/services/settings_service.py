import json
import configparser
from typing import Any
from pathlib import Path
from dotenv import dotenv_values, set_key
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings, get_config_file_path

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
    "OIDC_ENABLED": {"type": "bool", "category": "Single Sign-On (OIDC)", "description": "Enable OpenID Connect SSO"},
    "OIDC_ISSUER_URL": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Provider Issuer Discovery URL"},
    "OIDC_CLIENT_ID": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Client ID"},
    "OIDC_CLIENT_SECRET": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC Client Secret (Stored securely)"},
    "OIDC_REDIRECT_URI": {"type": "str", "category": "Single Sign-On (OIDC)", "description": "OIDC OAuth2 Redirect URI Callback"},
}


def read_file_settings() -> dict[str, str]:
    """Read raw setting key-value pairs from active config file (.env or config.ini)."""
    config_path = get_config_file_path()
    if not config_path.exists():
        return {}

    if config_path.suffix.lower() == ".ini":
        cp = configparser.ConfigParser()
        try:
            cp.read(str(config_path), encoding="utf-8")
            res: dict[str, str] = {}
            for sec in cp.sections():
                for k, v in cp.items(sec):
                    k_upper = k.upper()
                    if k_upper.startswith("DNS_WUI_"):
                        k_upper = k_upper[8:]
                    res[k_upper] = v
            return res
        except Exception:
            return {}
    else:
        try:
            raw_vals = dotenv_values(str(config_path))
            res = {}
            for k, v in raw_vals.items():
                if v is not None:
                    k_upper = k.upper()
                    if k_upper.startswith("DNS_WUI_"):
                        k_upper = k_upper[8:]
                    res[k_upper] = v
            return res
        except Exception:
            return {}


def parse_setting_value(val_str: Any, val_type: str) -> Any:
    """Parse string or typed value from config file or UI into typed python value."""
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


async def save_settings_to_file(
    new_settings: dict[str, Any], session: AsyncSession | None = None
) -> dict[str, Any]:
    """Persist settings to active config file (.env or config.ini) as staged configuration without auto-applying to live runtime."""
    config_path = get_config_file_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.touch(mode=0o640)

    saved = {}
    is_ini = config_path.suffix.lower() == ".ini"

    if is_ini:
        cp = configparser.ConfigParser()
        if config_path.exists():
            cp.read(str(config_path), encoding="utf-8")
        if "dns_wui" not in cp:
            cp["dns_wui"] = {}
        for key, raw_val in new_settings.items():
            if key not in CONFIGURABLE_FIELDS:
                continue
            meta = CONFIGURABLE_FIELDS[key]
            parsed_val = parse_setting_value(raw_val, meta["type"])
            if meta["type"] == "list":
                stored_str = json.dumps(parsed_val)
            elif meta["type"] == "bool":
                stored_str = "true" if parsed_val else "false"
            else:
                stored_str = str(parsed_val) if parsed_val is not None else ""
            cp["dns_wui"][key.lower()] = stored_str
            saved[key] = parsed_val
        with open(str(config_path), "w", encoding="utf-8") as f:
            cp.write(f)
    else:
        # .env file
        for key, raw_val in new_settings.items():
            if key not in CONFIGURABLE_FIELDS:
                continue
            meta = CONFIGURABLE_FIELDS[key]
            parsed_val = parse_setting_value(raw_val, meta["type"])
            if meta["type"] == "list":
                stored_str = json.dumps(parsed_val)
            elif meta["type"] == "bool":
                stored_str = "true" if parsed_val else "false"
            else:
                stored_str = str(parsed_val) if parsed_val is not None else ""

            set_key(str(config_path), key, stored_str, quote_mode="auto")
            saved[key] = parsed_val

    return saved


async def apply_saved_settings(session: AsyncSession | None = None) -> dict[str, Any]:
    """Load persistent settings from active config file (.env or config.ini) and apply into live runtime settings."""
    file_settings = read_file_settings()
    applied = {}
    for key, raw_val in file_settings.items():
        if key in CONFIGURABLE_FIELDS:
            meta = CONFIGURABLE_FIELDS[key]
            val = parse_setting_value(raw_val, meta["type"])
            settings.apply_override(key, val)
            applied[key] = val
    settings.ensure_directories()
    return applied


async def load_settings_from_file(session: AsyncSession | None = None) -> None:
    """Load settings overrides from active config file (.env or config.ini) into runtime settings."""
    await apply_saved_settings(session=session)


async def get_all_settings_view(session: AsyncSession | None = None) -> dict[str, Any]:
    """Return all settings with metadata, staged file value, live runtime value, and pending status."""
    file_map = read_file_settings()

    settings_list = []
    has_pending = False

    for key, meta in CONFIGURABLE_FIELDS.items():
        live_val = getattr(settings, key, None)
        if hasattr(live_val, "as_posix"):
            live_val = str(live_val)

        # Staged value in file if any, else live_val
        if key in file_map:
            staged_val = parse_setting_value(file_map[key], meta["type"])
        else:
            staged_val = live_val

        # Compare if staged != live
        is_pending = False
        if key in file_map:
            staged_norm = str(staged_val) if meta["type"] != "list" else json.dumps(staged_val)
            live_norm = str(live_val) if meta["type"] != "list" else json.dumps(live_val)
            if staged_norm != live_norm:
                is_pending = True
                has_pending = True

        settings_list.append({
            "key": key,
            "category": meta["category"],
            "type": meta["type"],
            "description": meta["description"],
            "choices": meta.get("choices"),
            "value": staged_val,
            "live_value": live_val,
            "is_pending": is_pending,
        })

    return {
        "settings": settings_list,
        "has_pending_changes": has_pending,
        "config_file": str(get_config_file_path()),
    }


# Backward-compatibility aliases
async def save_settings_to_db(session: Any, new_settings: dict[str, Any]) -> dict[str, Any]:
    return await save_settings_to_file(new_settings, session=session)


async def load_settings_from_db(session: Any = None) -> None:
    await load_settings_from_file(session=session)
