from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from app.api.deps import get_current_user, log_audit
from app.database import get_session
from app.models.user import User
from app.bind.overrides import list_overrides, set_override, delete_override

router = APIRouter(prefix="/overrides", tags=["overrides"])


class OverrideRequest(BaseModel):
    fqdn: str = Field(..., description="Target domain/hostname to override, e.g. nas.example.com")
    target: str = Field(..., description="Local LAN destination IP or CNAME FQDN")
    record_type: str = Field(default="A", description="A, AAAA, or CNAME")
    ttl: int = Field(default=300, description="TTL in seconds")


@router.get("")
async def get_all_overrides(_user: User = Depends(get_current_user)):
    """List all active local split-horizon DNS overrides."""
    overrides = list_overrides()
    return [
        {
            "fqdn": o.fqdn,
            "target": o.target,
            "record_type": o.record_type,
            "ttl": o.ttl,
        }
        for o in overrides
    ]


@router.post("")
async def create_or_update_override(
    body: OverrideRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """Add or update a local DNS override."""
    try:
        await set_override(
            fqdn=body.fqdn,
            target=body.target,
            record_type=body.record_type,
            ttl=body.ttl,
        )
        await log_audit(
            session=session,
            username=user.username,
            action="SET_OVERRIDE",
            zone_name="rpz.overrides.local",
            record_name=body.fqdn,
            record_type=body.record_type,
            details=f"Overriding {body.fqdn} -> {body.target} ({body.record_type})",
            status="SUCCESS",
        )
        return {"status": "success", "message": f"Override for '{body.fqdn}' saved and reloaded."}
    except Exception as e:
        await log_audit(
            session=session,
            username=user.username,
            action="SET_OVERRIDE",
            zone_name="rpz.overrides.local",
            record_name=body.fqdn,
            record_type=body.record_type,
            details=str(e),
            status="FAILURE",
        )
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{fqdn}")
async def remove_override(
    fqdn: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """Delete a local DNS override."""
    try:
        deleted = await delete_override(fqdn)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Override for '{fqdn}' not found.")

        await log_audit(
            session=session,
            username=user.username,
            action="DELETE_OVERRIDE",
            zone_name="rpz.overrides.local",
            record_name=fqdn,
            details=f"Deleted override for {fqdn}",
            status="SUCCESS",
        )
        return {"status": "success", "message": f"Override for '{fqdn}' removed."}
    except HTTPException:
        raise
    except Exception as e:
        await log_audit(
            session=session,
            username=user.username,
            action="DELETE_OVERRIDE",
            zone_name="rpz.overrides.local",
            record_name=fqdn,
            details=str(e),
            status="FAILURE",
        )
        raise HTTPException(status_code=400, detail=str(e))
