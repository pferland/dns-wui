import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.api.deps import get_current_user, require_role, log_audit
from app.database import get_session
from app.models.user import User
from app.models.api_key import ApiKey

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., description="Label or descriptive name for this key, e.g. 'Certbot ACME', 'Terraform CI'")
    role: str = Field(default="operator", description="Role to assign: 'operator' or 'admin'")
    expires_in_days: int | None = Field(default=None, description="Expiration in days (null for indefinite)")


@router.get("")
async def list_api_keys(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(require_role("admin")),
):
    """List all configured API automation keys."""
    res = await session.exec(select(ApiKey).order_by(ApiKey.id.desc()))
    keys = res.all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "prefix": k.prefix,
            "role": k.role,
            "created_at": k.created_at.isoformat(),
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        }
        for k in keys
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    req: CreateApiKeyRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("admin")),
):
    """Generate a new API key. The full key is displayed only once."""
    raw_secret = f"wui_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
    prefix = f"{raw_secret[:12]}..."

    expires_at = None
    if req.expires_in_days and req.expires_in_days > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(days=req.expires_in_days)

    api_key = ApiKey(
        name=req.name.strip(),
        prefix=prefix,
        key_hash=key_hash,
        role=req.role if req.role in ("admin", "operator") else "operator",
        user_id=user.id,
        expires_at=expires_at,
    )
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    await log_audit(
        session=session,
        username=user.username,
        action="CREATE_API_KEY",
        zone_name="system",
        details=f"Created API Key '{req.name}' (Role: {api_key.role})",
        status="SUCCESS",
    )

    return {
        "id": api_key.id,
        "name": api_key.name,
        "prefix": api_key.prefix,
        "role": api_key.role,
        "api_key": raw_secret,  # Displayed only once!
        "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
        "message": "Store this key securely. It will not be shown again.",
    }


@router.delete("/{key_id}")
async def revoke_api_key(
    key_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("admin")),
):
    """Revoke an API key immediately."""
    res = await session.exec(select(ApiKey).where(ApiKey.id == key_id))
    api_key = res.first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API Key not found.")

    await session.delete(api_key)
    await session.commit()

    await log_audit(
        session=session,
        username=user.username,
        action="REVOKE_API_KEY",
        zone_name="system",
        details=f"Revoked API Key '{api_key.name}' (ID: {key_id})",
        status="SUCCESS",
    )

    return {"status": "success", "message": f"API Key '{api_key.name}' revoked."}
