from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class ApiKey(SQLModel, table=True):
    __tablename__ = "api_keys"

    id: int | None = Field(default=None, primary_key=True)
    name: str
    prefix: str = Field(index=True)  # e.g. "wui_a8b9..."
    key_hash: str                    # SHA-256 hash of the full token
    role: str = Field(default="operator")  # "admin" or "operator"
    user_id: int | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = Field(default=None)
    last_used_at: datetime | None = Field(default=None)
