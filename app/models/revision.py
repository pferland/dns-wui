from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class ZoneRevision(SQLModel, table=True):
    __tablename__ = "zone_revisions"

    id: int | None = Field(default=None, primary_key=True)
    zone_name: str = Field(index=True)
    content: str
    serial: int | None = Field(default=None)
    author: str = Field(default="system")
    comment: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
