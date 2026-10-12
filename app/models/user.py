from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    is_admin: bool = Field(default=False)
    role: str = Field(default="admin")  # "admin", "operator", "viewer"
    totp_secret: str | None = Field(default=None)
    totp_enabled: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
