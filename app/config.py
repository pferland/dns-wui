import os
import shutil
import configparser
from pathlib import Path
from typing import Literal, Any, Tuple, Type
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    PydanticBaseSettingsSource,
    EnvSettingsSource,
    DotEnvSettingsSource,
)


def get_config_file_path() -> Path:
    """Resolve the active configuration file (.env or config.ini)."""
    custom = (
        os.environ.get("DNS_WUI_ENV_FILE")
        or os.environ.get("ENV_FILE")
        or os.environ.get("DNS_WUI_CONFIG_FILE")
    )
    if custom:
        return Path(custom)

    candidates = [
        Path.cwd() / "config.ini",
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / "config.ini",
        Path(__file__).resolve().parent.parent / ".env",
        Path("/opt/dns-wui/config.ini"),
        Path("/opt/dns-wui/.env"),
    ]
    for c in candidates:
        if c.exists():
            return c

    # Default to .env in project root if available, otherwise cwd
    project_root = Path(__file__).resolve().parent.parent
    if (project_root / "pyproject.toml").exists():
        return project_root / ".env"
    return Path.cwd() / ".env"


class IniFileSettingsSource(PydanticBaseSettingsSource):
    """Configuration source that reads key-value pairs from an INI file."""

    def __init__(self, settings_cls: Type[BaseSettings], ini_path: Path):
        super().__init__(settings_cls)
        self.ini_path = ini_path

    def get_field_value(self, field, field_name):
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.ini_path and self.ini_path.exists() and self.ini_path.suffix.lower() == ".ini":
            cp = configparser.ConfigParser()
            try:
                cp.read(str(self.ini_path), encoding="utf-8")
                for sec in cp.sections():
                    for k, v in cp.items(sec):
                        k_upper = k.upper()
                        if k_upper.startswith("DNS_WUI_"):
                            k_upper = k_upper[8:]
                        data[k_upper] = v
            except Exception:
                pass
        return data


def detect_bind_conf() -> Path:
    candidates = [
        Path("/etc/bind/named.conf"),
        Path("/etc/bind/named.conf.local"),
        Path("/etc/named.conf"),
        Path("./data/named.conf"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return Path("./data/named.conf")


def detect_zones_dir() -> Path:
    candidates = [
        Path("/etc/bind/zones"),
        Path("/etc/bind"),
        Path("/var/named"),
        Path("./data/zones"),
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return Path("./data/zones")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(get_config_file_path()),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "BIND 9 DNS Manager"
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8008
    BASE_URL: str = "http://localhost:8008"
    DATA_DIR: Path = Path("./data")
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/dns_wui.db"

    # BIND 9 Paths & Binaries
    NAMED_CONF: Path = detect_bind_conf()
    ZONES_DIR: Path = detect_zones_dir()
    CHECKZONE_BIN: str | None = shutil.which("named-checkzone")
    CHECKCONF_BIN: str | None = shutil.which("named-checkconf")
    RNDC_BIN: str | None = shutil.which("rndc")
    USE_SUDO_FOR_RNDC: bool = False

    # SOA & PTR Configuration
    DEFAULT_SOA_STRATEGY: Literal["date_revision", "increment"] = "date_revision"
    AUTO_PTR_SYNC: bool = True
    OVERRIDE_ZONE_NAME: str = "rpz.overrides.local"
    OVERRIDE_ZONE_FILE: Path | None = None  # defaults to ZONES_DIR / "rpz.overrides.local"
    IGNORED_ZONES: list[str] = [
        "rpz.adblock.spam.local",
        "0.in-addr.arpa",
        "127.in-addr.arpa",
        "255.in-addr.arpa",
        "10.in-addr.arpa",
        "16.172.in-addr.arpa",
        "168.192.in-addr.arpa",
        "17.172.in-addr.arpa",
        "18.172.in-addr.arpa",
        "19.172.in-addr.arpa",
        "20.172.in-addr.arpa",
        "21.172.in-addr.arpa",
        "22.172.in-addr.arpa",
        "23.172.in-addr.arpa",
        "24.172.in-addr.arpa",
        "25.172.in-addr.arpa",
        "26.172.in-addr.arpa",
        "27.172.in-addr.arpa",
        "28.172.in-addr.arpa",
        "29.172.in-addr.arpa",
        "30.172.in-addr.arpa",
        "31.172.in-addr.arpa",
        "localhost",
        "local",
        "empty",
        "0",
        "127",
        "255",
        ".",
    ]

    # Security & Auth
    AUTH_MODE: Literal["local", "hybrid", "none"] = "hybrid"
    JWT_SECRET: str = "dns-wui-secret-key-change-in-production-32chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    # OIDC (Optional)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER_URL: str | None = None
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_REDIRECT_URI: str | None = None
    OIDC_ALLOWED_CLIENT_IDS: list[str] = ["dns-wui", "android-homenet-hub"]

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        cfg_path = get_config_file_path()
        sources: list[PydanticBaseSettingsSource] = [
            init_settings,
            env_settings,
            EnvSettingsSource(settings_cls, env_prefix="DNS_WUI_"),
        ]
        if cfg_path and cfg_path.suffix.lower() == ".ini":
            sources.append(IniFileSettingsSource(settings_cls, ini_path=cfg_path))
        else:
            sources.append(DotEnvSettingsSource(settings_cls, env_file=str(cfg_path)))
            sources.append(DotEnvSettingsSource(settings_cls, env_file=str(cfg_path), env_prefix="DNS_WUI_"))
        sources.append(file_secret_settings)
        return tuple(sources)

    def ensure_directories(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.ZONES_DIR.mkdir(parents=True, exist_ok=True)

    def apply_override(self, key: str, value: Any) -> None:
        """Dynamically update runtime configuration parameter."""
        if hasattr(self, key):
            # Convert paths
            if key in ("NAMED_CONF", "ZONES_DIR", "DATA_DIR", "OVERRIDE_ZONE_FILE"):
                if value is not None and str(value).strip():
                    value = Path(str(value).strip())
                else:
                    value = None
            object.__setattr__(self, key, value)
            if key == "ZONES_DIR" and self.ZONES_DIR:
                self.ensure_directories()

    def reload_from_file(self) -> None:
        """Reload configuration values from active config file (.env or config.ini)."""
        cfg_path = get_config_file_path()
        new_settings = Settings(_env_file=str(cfg_path) if cfg_path.exists() else None)
        for key in type(self).model_fields.keys():
            object.__setattr__(self, key, getattr(new_settings, key))
        self.ensure_directories()


settings = Settings()
