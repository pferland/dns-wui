from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class DdnsToken(SQLModel, table=True):
    __tablename__ = "ddns_tokens"

    id: int | None = Field(default=None, primary_key=True)
    name: str
    token_secret: str = Field(unique=True, index=True)
    token_hash: str = Field(unique=True, index=True)
    zone_name: str = Field(index=True)
    record_name: str
    last_ip: str | None = Field(default=None)
    last_updated_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
