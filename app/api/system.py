import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.api.deps import get_current_user, require_role, log_audit
from app.models.user import User
from app.bind.discovery import get_all_zones
from app.bind.validator import validate_named_conf
from app.bind.executor import (
    rndc_flush,
    rndc_flushname,
    rndc_reconfig,
    rndc_status,
    rndc_dumpdb,
)
from app.bind.overrides import list_overrides

router = APIRouter(prefix="/system", tags=["system"])


class FlushNameRequest(BaseModel):
    domain: str = Field(..., description="Domain name whose resolver cache should be flushed")


@router.get("/status")
async def system_status(_user: User = Depends(get_current_user)):
    zones = get_all_zones()
    forward = sum(1 for z in zones if not z.is_reverse)
    reverse = sum(1 for z in zones if z.is_reverse)

    return {
        "app_name": settings.APP_NAME,
        "named_conf_path": str(settings.NAMED_CONF),
        "named_conf_exists": settings.NAMED_CONF.exists(),
        "zones_dir": str(settings.ZONES_DIR),
        "zones_dir_exists": settings.ZONES_DIR.exists(),
        "checkzone_bin": settings.CHECKZONE_BIN,
        "checkconf_bin": settings.CHECKCONF_BIN,
        "rndc_bin": settings.RNDC_BIN,
        "total_zones": len(zones),
        "forward_zones": forward,
        "reverse_zones": reverse,
        "auth_mode": settings.AUTH_MODE,
        "auto_ptr_sync": settings.AUTO_PTR_SYNC,
    }


@router.post("/checkconf")
async def check_configuration(_user: User = Depends(get_current_user)):
    ok, msg = await validate_named_conf(settings.NAMED_CONF)
    return {"valid": ok, "message": msg}


@router.post("/rndc/flush")
async def trigger_rndc_flush(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Clear resolver cache: rndc flush."""
    ok, msg = await rndc_flush()
    await log_audit(
        session=session,
        username=user.username,
        action="RNDC_FLUSH",
        zone_name="system",
        details=f"rndc flush executed: {msg}",
        status="SUCCESS" if ok else "FAILURE",
    )
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@router.post("/rndc/flushname")
async def trigger_rndc_flushname(
    req: FlushNameRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("operator")),
):
    """Flush resolver cache for specific domain: rndc flushname <domain>."""
    ok, msg = await rndc_flushname(req.domain)
    await log_audit(
        session=session,
        username=user.username,
        action="RNDC_FLUSHNAME",
        zone_name=req.domain,
        details=f"rndc flushname {req.domain}: {msg}",
        status="SUCCESS" if ok else "FAILURE",
    )
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@router.post("/rndc/reconfig")
async def trigger_rndc_reconfig(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("admin")),
):
    """Reload configuration and newly defined zones: rndc reconfig."""
    ok, msg = await rndc_reconfig()
    await log_audit(
        session=session,
        username=user.username,
        action="RNDC_RECONFIG",
        zone_name="system",
        details=f"rndc reconfig: {msg}",
        status="SUCCESS" if ok else "FAILURE",
    )
    if not ok:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "success", "message": msg}


@router.get("/rndc/status")
async def trigger_rndc_status(_user: User = Depends(get_current_user)):
    """Fetch live status of BIND daemon: rndc status."""
    ok, msg = await rndc_status()
    return {"status": "success" if ok else "error", "output": msg}


@router.post("/rndc/dumpdb")
async def trigger_rndc_dumpdb(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_role("admin")),
):
    """Dump cache to dump file: rndc dumpdb -all."""
    ok, msg = await rndc_dumpdb()
    await log_audit(
        session=session,
        username=user.username,
        action="RNDC_DUMPDB",
        zone_name="system",
        details=f"rndc dumpdb: {msg}",
        status="SUCCESS" if ok else "FAILURE",
    )
    return {"status": "success" if ok else "error", "output": msg}


@router.get("/analytics")
async def get_system_analytics(_user: User = Depends(get_current_user)):
    """Get RPZ adblock stats, override counts, zone disk usage and BIND telemetry."""
    zones = get_all_zones(include_ignored=True)
    overrides = list_overrides()

    # Check RPZ adblock domain count
    adblock_count = 0
    adblock_size_mb = 0.0
    adblock_path = settings.ZONES_DIR / "rpz.adblock.spam.local"
    if not adblock_path.exists():
        adblock_path = Path("/var/cache/bind/zones/rpz.adblock.spam.local")

    if adblock_path.exists():
        try:
            stat = adblock_path.stat()
            adblock_size_mb = round(stat.st_size / (1024 * 1024), 2)
            # Estimate rules count by counting non-comment lines
            with adblock_path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith(";") and not s.startswith("$") and "CNAME" in s:
                        adblock_count += 1
        except Exception:
            pass

    # Disk usage
    total_disk_gb, used_disk_gb, free_disk_gb = 0, 0, 0
    if settings.ZONES_DIR.exists():
        du = shutil.disk_usage(str(settings.ZONES_DIR))
        total_disk_gb = round(du.total / (1024**3), 1)
        used_disk_gb = round(du.used / (1024**3), 1)
        free_disk_gb = round(du.free / (1024**3), 1)

    return {
        "total_zones": len([z for z in zones if not z.name.startswith("rpz.")]),
        "total_overrides": len(overrides),
        "adblock_rules": adblock_count,
        "adblock_size_mb": adblock_size_mb,
        "disk": {
            "total_gb": total_disk_gb,
            "used_gb": used_disk_gb,
            "free_gb": free_disk_gb,
        },
    }
