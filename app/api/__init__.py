from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.zones import router as zones_router
from app.api.records import router as records_router
from app.api.system import router as system_router
from app.api.audit import router as audit_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth_router)
api_router.include_router(zones_router)
api_router.include_router(records_router)
api_router.include_router(system_router)
api_router.include_router(audit_router)

__all__ = ["api_router"]
