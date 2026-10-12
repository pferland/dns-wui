from pathlib import Path
import shutil
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


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
        env_prefix="DNS_WUI_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "BIND 9 DNS Manager"
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8080
    BASE_URL: str = "http://localhost:8080"
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

    # Security & Auth
    AUTH_MODE: Literal["local", "hybrid", "none"] = "hybrid"
    JWT_SECRET: str = "dns-wui-secret-key-change-in-production-32chars"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    # TOTP 2FA
    TOTP_ENABLED: bool = True
    TOTP_ISSUER: str = "BIND9-DNS-WUI"

    # OIDC (Optional)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER_URL: str | None = None
    OIDC_CLIENT_ID: str | None = None
    OIDC_CLIENT_SECRET: str | None = None
    OIDC_REDIRECT_URI: str | None = None

    def ensure_directories(self) -> None:
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.ZONES_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
