import secrets
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from app.config import settings
from app.database import get_session
from app.models.user import User
from app.services.security import (
    verify_password,
    create_access_token,
    decode_access_token,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    generate_qr_code_base64,
)
from app.api.deps import get_current_user, log_audit
from app.services.oidc_service import (
    build_authorization_url,
    get_redirect_uri,
    process_oidc_callback,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    requires_2fa: bool = False
    temp_token: str | None = None
    username: str
    is_admin: bool


class Verify2faRequest(BaseModel):
    temp_token: str
    code: str


class Enable2faRequest(BaseModel):
    secret: str
    code: str


@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    res = await session.exec(select(User).where(User.username == credentials.username))
    user = res.first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if user.totp_enabled:
        temp_token = create_access_token(
            data={"sub": str(user.id), "scope": "2fa_pending"},
            expires_delta=timedelta(minutes=5),
        )
        return LoginResponse(
            requires_2fa=True,
            temp_token=temp_token,
            username=user.username,
            is_admin=user.is_admin,
        )

    token = create_access_token(data={"sub": str(user.id), "username": user.username})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRATION_HOURS * 3600,
    )
    return LoginResponse(
        access_token=token,
        requires_2fa=False,
        username=user.username,
        is_admin=user.is_admin,
    )


@router.post("/verify-2fa", response_model=LoginResponse)
async def verify_2fa_login(
    req: Verify2faRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
) -> LoginResponse:
    payload = decode_access_token(req.temp_token)
    if not payload or payload.get("scope") != "2fa_pending":
        raise HTTPException(status_code=400, detail="Invalid or expired 2FA session token")

    user_id = int(payload["sub"])
    res = await session.exec(select(User).where(User.id == user_id))
    user = res.first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="User not configured for 2FA")

    if not verify_totp(user.totp_secret, req.code):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")

    token = create_access_token(data={"sub": str(user.id), "username": user.username})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRATION_HOURS * 3600,
    )
    return LoginResponse(
        access_token=token,
        requires_2fa=False,
        username=user.username,
        is_admin=user.is_admin,
    )


@router.post("/2fa/setup")
async def setup_2fa(user: User = Depends(get_current_user)) -> dict[str, str]:
    """Generate new TOTP secret and QR code for scanning."""
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.username)
    qr_data_url = generate_qr_code_base64(uri)
    return {
        "secret": secret,
        "provisioning_uri": uri,
        "qr_code_url": qr_data_url,
    }


@router.post("/2fa/enable")
async def enable_2fa(
    req: Enable2faRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Verify code and permanently enable 2FA on account."""
    if not verify_totp(req.secret, req.code):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    user.totp_secret = req.secret
    user.totp_enabled = True
    session.add(user)
    await session.commit()
    return {"message": "Two-factor authentication enabled successfully"}


@router.post("/2fa/disable")
async def disable_2fa(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    user.totp_secret = None
    user.totp_enabled = False
    session.add(user)
    await session.commit()
    return {"message": "Two-factor authentication disabled"}


@router.post("/logout")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_me(user: User = Depends(get_current_user)) -> dict[str, str | bool | int]:
    return {
        "id": user.id or 0,
        "username": user.username,
        "is_admin": user.is_admin,
        "totp_enabled": user.totp_enabled,
    }


@router.get("/oidc/login")
async def oidc_api_login(request: Request) -> RedirectResponse:
    if not settings.OIDC_ENABLED or not settings.OIDC_ISSUER_URL or not settings.OIDC_CLIENT_ID:
        raise HTTPException(status_code=400, detail="OIDC Single Sign-On is not enabled or configured")

    state = secrets.token_urlsafe(16)
    auth_url, _ = await build_authorization_url(state=state, request=request)
    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="oidc_state",
        value=state,
        httponly=True,
        samesite="lax",
        max_age=300,
    )
    return response


@router.get("/oidc/callback")
async def oidc_api_callback(
    request: Request,
    response: Response,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> RedirectResponse:
    if error:
        err_msg = error_description or error or "OIDC login canceled or rejected"
        return RedirectResponse(url=f"/login?error={err_msg}")

    if not code:
        return RedirectResponse(url="/login?error=Missing+authorization+code+from+identity+provider")

    cookie_state = request.cookies.get("oidc_state")
    if cookie_state and state and cookie_state != state:
        return RedirectResponse(url="/login?error=Invalid+session+state.+Please+try+logging+in+again.")

    redirect_uri = get_redirect_uri(request)
    try:
        user, jwt_token = await process_oidc_callback(code=code, session=session, redirect_uri=redirect_uri)
    except Exception as e:
        return RedirectResponse(url=f"/login?error=SSO+Authentication+Failed:+{e}")

    await log_audit(
        session=session,
        username=user.username,
        action="LOGIN_OIDC",
        zone_name="AUTH",
        details=f"Successful SSO login via OIDC ({user.role})",
    )

    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key="access_token",
        value=jwt_token,
        httponly=True,
        samesite="lax",
        max_age=settings.JWT_EXPIRATION_HOURS * 3600,
    )
    redirect.delete_cookie("oidc_state")
    return redirect
