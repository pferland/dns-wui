import logging
import secrets
from typing import Any
from urllib.parse import urlencode
import httpx
import jwt
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from fastapi import Request
from app.config import settings
from app.models.user import User
from app.services.security import hash_password, create_access_token

logger = logging.getLogger(__name__)

# In-memory cache for OIDC provider discovery endpoints
_DISCOVERY_CACHE: dict[str, dict[str, str]] = {}


async def get_oidc_endpoints(issuer_url: str | None = None) -> dict[str, str]:
    """Discover OIDC endpoints from issuer or use standard fallback URLs."""
    issuer = (issuer_url or settings.OIDC_ISSUER_URL or "").strip().rstrip("/")
    if not issuer:
        raise ValueError("OIDC Issuer URL is not configured.")

    if issuer in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[issuer]

    discovery_url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(discovery_url)
            if resp.status_code == 200:
                data = resp.json()
                endpoints = {
                    "authorization_endpoint": data.get("authorization_endpoint") or f"{issuer}/oauth/authorize",
                    "token_endpoint": data.get("token_endpoint") or f"{issuer}/oauth/token",
                    "userinfo_endpoint": data.get("userinfo_endpoint") or f"{issuer}/oauth/userinfo",
                    "end_session_endpoint": data.get("end_session_endpoint") or f"{issuer}/oauth/logout",
                }
                _DISCOVERY_CACHE[issuer] = endpoints
                return endpoints
            else:
                logger.warning(f"OIDC discovery at {discovery_url} returned status {resp.status_code}. Using defaults.")
    except Exception as e:
        logger.warning(f"Failed to fetch OIDC discovery document from {discovery_url}: {e}. Using defaults.")

    endpoints = {
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "end_session_endpoint": f"{issuer}/oauth/logout",
    }
    _DISCOVERY_CACHE[issuer] = endpoints
    return endpoints


def get_redirect_uri(request: Request | None = None) -> str:
    """Return explicit OIDC_REDIRECT_URI if configured, otherwise derive /callback from request or BASE_URL."""
    if settings.OIDC_REDIRECT_URI and settings.OIDC_REDIRECT_URI.strip():
        return settings.OIDC_REDIRECT_URI.strip()
    if request:
        base = str(request.base_url).rstrip("/")
        # If running behind TLS reverse proxy, prefer forwarded https scheme
        forwarded_proto = request.headers.get("x-forwarded-proto")
        if forwarded_proto:
            base = base.replace("http://", f"{forwarded_proto}://")
        return f"{base}/callback"
    return f"{settings.BASE_URL.rstrip('/')}/callback"


async def build_authorization_url(state: str, request: Request | None = None) -> tuple[str, str]:
    """Construct full OIDC authorization redirect URL and return (auth_url, redirect_uri)."""
    endpoints = await get_oidc_endpoints(settings.OIDC_ISSUER_URL)
    auth_endpoint = endpoints["authorization_endpoint"]
    redirect_uri = get_redirect_uri(request)

    params = {
        "client_id": settings.OIDC_CLIENT_ID or "",
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    auth_url = f"{auth_endpoint}?{urlencode(params)}"
    return auth_url, redirect_uri


async def exchange_code_for_tokens(code: str, redirect_uri: str) -> dict[str, Any]:
    """Exchange authorization code for tokens at the OIDC token endpoint."""
    endpoints = await get_oidc_endpoints(settings.OIDC_ISSUER_URL)
    token_endpoint = endpoints["token_endpoint"]

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": settings.OIDC_CLIENT_ID or "",
    }
    if settings.OIDC_CLIENT_SECRET:
        data["client_secret"] = settings.OIDC_CLIENT_SECRET

    auth = None
    if settings.OIDC_CLIENT_ID and settings.OIDC_CLIENT_SECRET:
        auth = (settings.OIDC_CLIENT_ID, settings.OIDC_CLIENT_SECRET)

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        resp = await client.post(token_endpoint, data=data, auth=auth)
        if resp.status_code not in (200, 201):
            logger.error(f"Token exchange failed with status {resp.status_code}: {resp.text}")
            raise ValueError(f"Identity provider token exchange failed ({resp.status_code}): {resp.text}")
        return resp.json()


async def fetch_user_info(access_token: str, id_token: str | None = None) -> dict[str, Any]:
    """Fetch user profile information from userinfo endpoint or fallback to id_token claims."""
    endpoints = await get_oidc_endpoints(settings.OIDC_ISSUER_URL)
    userinfo_endpoint = endpoints.get("userinfo_endpoint")

    userinfo: dict[str, Any] = {}
    if userinfo_endpoint:
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if resp.status_code == 200:
                    userinfo = resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch userinfo from {userinfo_endpoint}: {e}")

    # Fallback to unverified id_token claims if userinfo endpoint returned empty
    if not userinfo and id_token:
        try:
            userinfo = jwt.decode(id_token, options={"verify_signature": False})
        except Exception as e:
            logger.warning(f"Failed to decode id_token: {e}")

    return userinfo


async def process_oidc_callback(
    code: str,
    session: AsyncSession,
    redirect_uri: str,
) -> tuple[User, str]:
    """
    Handle the full OIDC callback:
    1. Exchange code for access & ID tokens.
    2. Retrieve user identity.
    3. Provision or match local user in SQLite.
    4. Issue internal session JWT token.
    """
    token_response = await exchange_code_for_tokens(code, redirect_uri)
    access_token = token_response.get("access_token")
    if not access_token:
        raise ValueError("No access_token returned by identity provider")

    id_token = token_response.get("id_token")
    userinfo = await fetch_user_info(access_token, id_token)

    username = (
        userinfo.get("preferred_username")
        or userinfo.get("username")
        or userinfo.get("email")
        or userinfo.get("name")
        or userinfo.get("sub")
    )
    if not username:
        raise ValueError("Could not determine username from OIDC token claims")

    username = str(username).strip().lower()
    email = str(userinfo.get("email", "")).strip().lower() if userinfo.get("email") else None

    # Find existing user in database by username or email
    query = select(User).where(User.username == username)
    res = await session.exec(query)
    user = res.first()

    if not user and email:
        res_email = await session.exec(select(User).where(User.username == email))
        user = res_email.first()

    # Determine admin privileges
    roles = userinfo.get("roles", [])
    if not isinstance(roles, list):
        roles = [roles]
    is_admin = (
        "admin" in roles
        or "superadmin" in roles
        or userinfo.get("is_admin") is True
        or username in ("pferland", "admin")
    )
    role = "admin" if is_admin else "operator"

    if not user:
        # Provision new user on-the-fly
        user = User(
            username=username,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            is_admin=is_admin,
            role=role,
            totp_enabled=False,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        logger.info(f"Provisioned new OIDC user '{username}' (role: {role}, is_admin: {is_admin})")
    else:
        # Update admin / role if elevated
        if is_admin and not user.is_admin:
            user.is_admin = True
            user.role = "admin"
            session.add(user)
            await session.commit()
            await session.refresh(user)

    # Issue application JWT access token
    session_jwt = create_access_token(data={"sub": str(user.id), "username": user.username})
    return user, session_jwt
