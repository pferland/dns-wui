import hashlib
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Request, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.models.audit import AuditLog
from app.models.api_key import ApiKey
from app.services.security import decode_access_token

ROLE_HIERARCHY = {
    "admin": 3,
    "operator": 2,
    "viewer": 1,
}


async def get_current_user_optional(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> User | None:
    if settings.AUTH_MODE == "none":
        res = await session.exec(select(User).where(User.username == settings.ADMIN_USERNAME))
        return res.first()

    raw_token: str | None = None

    # 1. Check X-API-Key header
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        raw_token = api_key_header.strip()

    # 2. Check Authorization Bearer header
    if not raw_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()

    # 3. Check Cookie
    if not raw_token and "access_token" in request.cookies:
        raw_token = request.cookies.get("access_token")

    if not raw_token:
        return None

    # Handle API Key authentication (starts with "wui_")
    if raw_token.startswith("wui_"):
        key_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        res = await session.exec(select(ApiKey).where(ApiKey.key_hash == key_hash))
        api_key = res.first()
        if api_key:
            # Check expiration
            if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
                return None
            api_key.last_used_at = datetime.now(timezone.utc)
            session.add(api_key)
            await session.commit()

            return User(
                id=api_key.user_id or 99999,
                username=f"api:{api_key.name}",
                hashed_password="",
                is_admin=(api_key.role == "admin"),
                role=api_key.role,
                totp_enabled=False,
            )
        return None

    # Handle standard JWT tokens
    payload = decode_access_token(raw_token)
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


def require_role(min_role: str):
    """Dependency that enforces a minimum RBAC role ('admin', 'operator', 'viewer')."""
    async def role_checker(user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_HIERARCHY.get(getattr(user, "role", "viewer"), 1)
        # If user is_admin, grant full admin level
        if getattr(user, "is_admin", False):
            user_level = 3
        required_level = ROLE_HIERARCHY.get(min_role, 1)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: operation requires '{min_role}' role (current role: '{getattr(user, 'role', 'viewer')}').",
            )
        return user
    return role_checker


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
        zone_name=zone_name or "SYSTEM",
        record_name=record_name,
        record_type=record_type,
        details=details,
        status=status,
    )

    session.add(audit_entry)
    await session.commit()
