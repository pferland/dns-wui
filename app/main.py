from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from fastapi import FastAPI, Request, Depends, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
import logging

from app.config import settings
from app.database import init_db, get_session
from app.models.user import User
from app.models.audit import AuditLog
from app.api import api_router
from app.api.deps import get_current_user_optional
from app.services.security import (
    verify_password,
    create_access_token,
    decode_access_token,
    verify_totp,
)
from app.bind.discovery import get_all_zones
from app.bind.parser import parse_zone_file

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dns-wui")

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing DNS-WUI database and environment...")
    await init_db()
    settings.ensure_directories()
    logger.info("DNS-WUI initialized and ready.")
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app.include_router(api_router)


# --- HTML Web UI Routes ---


from app.api.zones import _quick_inspect_zone


@app.get("/", response_class=HTMLResponse)
async def index_page(
    request: Request,
    include_ignored: bool = False,
    type: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    if not user and settings.AUTH_MODE not in ("none",):
        return RedirectResponse(url="/login")

    all_discovered = get_all_zones(include_ignored=include_ignored)
    forward_total = sum(1 for z in all_discovered if not z.is_reverse)
    reverse_total = sum(1 for z in all_discovered if z.is_reverse)

    filtered_zones = all_discovered
    if type == "forward":
        filtered_zones = [z for z in all_discovered if not z.is_reverse]
    elif type == "reverse":
        filtered_zones = [z for z in all_discovered if z.is_reverse]

    zone_list = []
    for z in filtered_zones:
        record_count = 0
        serial = None
        if z.file_path.exists():
            record_count, serial = _quick_inspect_zone(z.file_path)

        zone_list.append({
            "name": z.name,
            "file_path": str(z.file_path),
            "zone_type": z.zone_type,
            "is_reverse": z.is_reverse,
            "source": z.source,
            "record_count": record_count,
            "serial": serial,
        })

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "active_page": "zones",
            "filter_type": type,
            "bind_host": "192.168.1.3",
            "zones": zone_list,
            "forward_count": forward_total,
            "reverse_count": reverse_total,
            "zones_dir": str(settings.ZONES_DIR),
            "include_ignored": include_ignored,
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request, user: User | None = Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/")
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "user": None,
            "step": "credentials",
            "error": None,
            "active_page": "login",
        },
    )


@app.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    res = await session.exec(select(User).where(User.username == username))
    user = res.first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "user": None,
                "step": "credentials",
                "error": "Invalid username or password",
                "active_page": "login",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if user.totp_enabled:
        temp_token = create_access_token(
            data={"sub": str(user.id), "scope": "2fa_pending"},
            expires_delta=timedelta(minutes=5),
        )
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "user": None,
                "step": "2fa",
                "temp_token": temp_token,
                "error": None,
                "active_page": "login",
            },
        )

    token = create_access_token(data={"sub": str(user.id), "username": user.username})
    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRATION_HOURS * 3600,
    )
    return redirect


@app.post("/login/2fa", response_class=HTMLResponse)
async def login_2fa_post(
    request: Request,
    temp_token: str = Form(...),
    code: str = Form(...),
    session: AsyncSession = Depends(get_session),
):
    payload = decode_access_token(temp_token)
    if not payload or payload.get("scope") != "2fa_pending":
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "user": None,
                "step": "credentials",
                "error": "2FA session expired. Please sign in again.",
                "active_page": "login",
            },
        )

    user_id = int(payload["sub"])
    res = await session.exec(select(User).where(User.id == user_id))
    user = res.first()
    if not user or not user.totp_secret or not verify_totp(user.totp_secret, code):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "user": None,
                "step": "2fa",
                "temp_token": temp_token,
                "error": "Invalid verification code. Please check your authenticator app.",
                "active_page": "login",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    token = create_access_token(data={"sub": str(user.id), "username": user.username})
    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRATION_HOURS * 3600,
    )
    return redirect


@app.get("/logout")
async def logout_get():
    redirect = RedirectResponse(url="/login")
    redirect.delete_cookie("access_token")
    return redirect


@app.get("/zones/{zone_name}", response_class=HTMLResponse)
async def zone_detail_page(
    zone_name: str,
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    if not user and settings.AUTH_MODE not in ("none",):
        return RedirectResponse(url="/login")

    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        return RedirectResponse(url="/")

    try:
        model = parse_zone_file(matched.file_path, origin=matched.name)
    except Exception as e:
        logger.error(f"Error parsing zone {matched.name}: {e}")
        return RedirectResponse(url="/")

    return templates.TemplateResponse(
        request=request,
        name="zone_detail.html",
        context={
            "user": user,
            "active_page": "zones",
            "zone": {
                "name": matched.name,
                "origin": model.origin,
                "file_path": str(matched.file_path),
                "is_reverse": matched.is_reverse,
                "default_ttl": model.default_ttl,
                "soa": model.soa,
                "records": model.records,
            },
        },
    )


@app.get("/zones/{zone_name}/raw", response_class=HTMLResponse)
async def raw_zone_page(
    zone_name: str,
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    if not user and settings.AUTH_MODE not in ("none",):
        return RedirectResponse(url="/login")

    zones = get_all_zones()
    matched = next((z for z in zones if z.name.rstrip(".").lower() == zone_name.rstrip(".").lower()), None)
    if not matched or not matched.file_path.exists():
        return RedirectResponse(url="/")

    content = matched.file_path.read_text(encoding="utf-8")
    return templates.TemplateResponse(
        request=request,
        name="raw_editor.html",
        context={
            "user": user,
            "active_page": "zones",
            "zone_name": matched.name,
            "content": content,
        },
    )


@app.get("/2fa", response_class=HTMLResponse)
async def two_factor_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    if not user:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse(
        request=request,
        name="two_factor.html",
        context={
            "user": user,
            "active_page": "2fa",
        },
    )


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(get_current_user_optional),
):
    if not user and settings.AUTH_MODE not in ("none",):
        return RedirectResponse(url="/login")

    result = await session.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(100))
    logs = result.all()

    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "user": user,
            "active_page": "audit",
            "logs": logs,
        },
    )


@app.get("/system", response_class=HTMLResponse)
async def system_page(
    request: Request,
    user: User | None = Depends(get_current_user_optional),
):
    if not user and settings.AUTH_MODE not in ("none",):
        return RedirectResponse(url="/login")

    zones = get_all_zones()
    status_info = {
        "named_conf_path": str(settings.NAMED_CONF),
        "named_conf_exists": settings.NAMED_CONF.exists(),
        "zones_dir": str(settings.ZONES_DIR),
        "zones_dir_exists": settings.ZONES_DIR.exists(),
        "checkzone_bin": settings.CHECKZONE_BIN,
        "checkconf_bin": settings.CHECKCONF_BIN,
        "rndc_bin": settings.RNDC_BIN,
        "auto_ptr_sync": settings.AUTO_PTR_SYNC,
    }

    return templates.TemplateResponse(
        request=request,
        name="system.html",
        context={
            "user": user,
            "active_page": "system",
            "status": status_info,
        },
    )
