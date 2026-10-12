from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from app.api.deps import get_current_user, require_role, log_audit
from app.database import get_session
from app.models.user import User
from app.bind.adblock import (
    get_adblock_summary,
    add_adblock_whitelist,
    remove_adblock_whitelist,
    update_adblock_from_upstream,
    DEFAULT_BLOCKLIST_SOURCE,
)

router = APIRouter(prefix="/adblock", tags=["adblock"])


class WhitelistRequest(BaseModel):
    domain: str = Field(..., description="Domain name to whitelist from adblocking, e.g. 'analytics.example.com'")


class UpdateBlocklistRequest(BaseModel):
    source_url: str = Field(default=DEFAULT_BLOCKLIST_SOURCE, description="URL of hosts format blocklist")


@router.get("/summary")
async def adblock_summary(_user: User = Depends(get_current_user)):
    """Retrieve ad-blocking statistics and active whitelist."""
    return get_adblock_summary()


@router.post("/whitelist")
async def add_whitelist(
    req: WhitelistRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Add a domain to the RPZ ad-blocking whitelist (passthrough)."""
    try:
        await add_adblock_whitelist(req.domain)
        await log_audit(
            session=session,
            username=user.username,
            action="ADBLOCK_WHITELIST_ADD",
            zone_name="rpz.adblock.spam.local",
            record_name=req.domain,
            details=f"Whitelisted '{req.domain}' from RPZ adblock",
        )
        return {"status": "success", "message": f"Domain '{req.domain}' whitelisted."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/whitelist/{domain}")
async def remove_whitelist(
    domain: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Remove a domain from the RPZ ad-blocking whitelist."""
    try:
        deleted = await remove_adblock_whitelist(domain)
        if not deleted:
            raise HTTPException(status_code=404, detail="Domain not in whitelist")

        await log_audit(
            session=session,
            username=user.username,
            action="ADBLOCK_WHITELIST_DEL",
            zone_name="rpz.adblock.spam.local",
            record_name=domain,
            details=f"Removed '{domain}' from RPZ whitelist",
        )
        return {"status": "success", "message": f"Domain '{domain}' removed from whitelist."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/update")
async def trigger_blocklist_update(
    req: UpdateBlocklistRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("admin")),
):
    """Download latest upstream blocklists, compile into RPZ format, and reload BIND."""
    try:
        result = await update_adblock_from_upstream(req.source_url)
        await log_audit(
            session=session,
            username=user.username,
            action="ADBLOCK_UPDATE",
            zone_name="rpz.adblock.spam.local",
            details=f"Updated blocklist from {req.source_url} ({result['rules_count']} rules compiled)",
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
