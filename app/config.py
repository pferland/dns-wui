from pathlib import Path
import shutil
from typing import Literal, Any
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


settings = Settings()

