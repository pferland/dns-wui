import base64
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt
from jwt import PyJWKClient
import pyotp
import qrcode
from app.config import settings

_ph = PasswordHasher()
_jwks_client: PyJWKClient | None = None


def get_jwks_client() -> PyJWKClient | None:
    global _jwks_client
    if not settings.OIDC_ENABLED or not settings.OIDC_ISSUER_URL:
        return None
    if _jwks_client is None:
        jwks_url = f"{settings.OIDC_ISSUER_URL.rstrip('/')}/.well-known/jwks.json"
        _jwks_client = PyJWKClient(jwks_url, cache_keys=True, max_cached_keys=16)
    return _jwks_client


def verify_oidc_bearer_token(token: str) -> dict[str, Any] | None:
    """Validate an RS256 Bearer JWT against the OIDC Identity Provider (SimpleTessera) via JWKS."""
    if not settings.OIDC_ENABLED or not settings.OIDC_ISSUER_URL:
        return None
    try:
        jwks_client = get_jwks_client()
        if not jwks_client:
            return None
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            options={"verify_aud": False, "verify_exp": True},
        )
        expected_issuer = settings.OIDC_ISSUER_URL.rstrip("/")
        token_issuer = str(claims.get("iss", "")).rstrip("/")
        if expected_issuer and token_issuer and expected_issuer != token_issuer:
            return None

        allowed_clients = getattr(settings, "OIDC_ALLOWED_CLIENT_IDS", None)
        if allowed_clients:
            token_client = claims.get("client_id") or claims.get("aud")
            if token_client and token_client not in allowed_clients:
                return None

        return claims
    except Exception:
        return None


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, Exception):
        return False


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRATION_HOURS)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None


# --- TOTP 2FA Helpers ---

def generate_totp_secret() -> str:
    """Generate a base32 TOTP secret key."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Generate standard otpauth:// URI."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.TOTP_ISSUER)


def verify_totp(secret: str, token: str) -> bool:
    """Verify a 6-digit TOTP code against secret, allowing 1 step window for clock drift."""
    if not secret or not token:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token.strip(), valid_window=1)


def generate_qr_code_base64(uri: str) -> str:
    """Generate a base64 encoded PNG QR code image data URL."""
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    b64_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"
