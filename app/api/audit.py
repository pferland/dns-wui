from fastapi import APIRouter, Depends
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.database import get_session
from app.models.audit import AuditLog
from app.api.deps import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def get_audit_logs(
    limit: int = 50,
    session: AsyncSession = Depends(get_session),
    _user=Depends(get_current_user),
):
    result = await session.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    logs = result.all()
    return logs
