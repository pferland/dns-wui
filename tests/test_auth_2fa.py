import pyotp
from app.services.security import (
    hash_password,
    verify_password,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    generate_qr_code_base64,
)


def test_password_argon2():
    pwd = "super-secret-password-123"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrong-password", hashed) is False


def test_totp_2fa_lifecycle():
    secret = generate_totp_secret()
    assert len(secret) == 32

    uri = get_totp_uri(secret, "admin")
    assert "otpauth://totp/" in uri
    assert "admin" in uri

    qr = generate_qr_code_base64(uri)
    assert qr.startswith("data:image/png;base64,")

    # Generate current valid code with pyotp
    totp = pyotp.TOTP(secret)
    current_code = totp.now()

    assert verify_totp(secret, current_code) is True
    assert verify_totp(secret, "000000") is False
