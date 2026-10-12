from fastapi import Depends, HTTPException, Request, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.models.audit import AuditLog
from app.services.security import decode_access_token


async def get_current_user_optional(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User | None:
    if settings.AUTH_MODE == "none":
        res = await session.exec(select(User).where(User.username == settings.ADMIN_USERNAME))
        return res.first()

    token: str | None = None

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()

    if not token and "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if token:
        payload = decode_access_token(token)
        if payload and "sub" in payload:
            user_id = payload["sub"]
            try:
                res = await session.exec(select(User).where(User.id == int(user_id)))
                user = res.first()
                if user:
                    return user
            except (ValueError, TypeError):
                res = await session.exec(select(User).where(User.username == str(user_id)))
                user = res.first()
                if user:
                    return user

    return None


async def get_current_user(
    user: User | None = Depends(get_current_user_optional),
) -> User:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def log_audit(
    session: AsyncSession,
    username: str,
    action: str,
    zone_name: str,
    record_name: str | None = None,
    record_type: str | None = None,
    details: str = "",
    status: str = "SUCCESS",
) -> None:
    audit_entry = AuditLog(
        username=username,
        action=action,
        zone_name=zone_name,
        record_name=record_name,
        record_type=record_type,
        details=details,
        status=status,
    )
    session.add(audit_entry)
    await session.commit()
