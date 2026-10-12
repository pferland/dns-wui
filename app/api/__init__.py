from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.zones import router as zones_router
from app.api.records import router as records_router
from app.api.system import router as system_router
from app.api.audit import router as audit_router
from app.api.overrides import router as overrides_router
from app.api.tools import router as tools_router
from app.api.api_keys import router as api_keys_router
from app.api.ddns import router as ddns_router
from app.api.adblock import router as adblock_router
from app.api.backups import router as backups_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(zones_router)
api_router.include_router(records_router)
api_router.include_router(system_router)
api_router.include_router(audit_router)
api_router.include_router(overrides_router)
api_router.include_router(tools_router)
api_router.include_router(api_keys_router)
api_router.include_router(ddns_router)
api_router.include_router(adblock_router)
api_router.include_router(backups_router)

__all__ = ["api_router"]

