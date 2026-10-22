"""Configuration models. Deprecated: configuration is stored in .env or config.ini rather than SQLite."""
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class AppSetting(SQLModel, table=False):
    key: str = Field(primary_key=True)
    value: str = Field(default="")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
