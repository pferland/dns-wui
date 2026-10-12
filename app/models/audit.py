from datetime import datetime, timezone
from sqlmodel import SQLModel, Field


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_logs"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), index=True)
    username: str = Field(index=True)
    action: str = Field(index=True)  # e.g. ADD_RECORD, EDIT_RECORD, DELETE_RECORD, RELOAD_ZONE
    zone_name: str = Field(index=True)
    record_name: str | None = None
    record_type: str | None = None
    details: str = Field(default="")
    status: str = Field(default="SUCCESS")  # SUCCESS, FAILED
