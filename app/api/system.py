from fastapi import APIRouter, Depends
from app.config import settings
from app.api.deps import get_current_user
from app.bind.discovery import get_all_zones
from app.bind.validator import validate_named_conf

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/status")
async def system_status(_user=Depends(get_current_user)):
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
async def check_configuration(_user=Depends(get_current_user)):
    ok, msg = await validate_named_conf(settings.NAMED_CONF)
    return {"valid": ok, "message": msg}
