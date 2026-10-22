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
