"""
CyberSleuth AI – Security Utilities
Member 2: Backend & Data Engineering

JWT token creation/verification and password hashing.
Supports python-jose, PyJWT, or built-in HMAC-SHA256 fallback.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import json
import base64
import hmac
import hashlib

from .config import settings

# ── Password helpers ───────────────────────────────────────────────────────────
try:
    import bcrypt

    def hash_password(plain: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")

    def verify_password(plain: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

except ImportError:
    # Safe hashlib fallback
    def hash_password(plain: str) -> str:
        salt = "cybersleuth_salt"
        return hashlib.sha256(f"{salt}:{plain}".encode()).hexdigest()

    def verify_password(plain: str, hashed: str) -> bool:
        salt = "cybersleuth_salt"
        return hashlib.sha256(f"{salt}:{plain}".encode()).hexdigest() == hashed


# ── JWT helpers ────────────────────────────────────────────────────────────────
_jwt_lib = None
try:
    from jose import jwt, JWTError
    _jwt_lib = "jose"
except ImportError:
    try:
        import jwt
        from jwt import PyJWTError as JWTError
        _jwt_lib = "pyjwt"
    except ImportError:
        _jwt_lib = "custom"


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding and padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {"sub": subject, "exp": int(expire.timestamp())}

    if _jwt_lib in ("jose", "pyjwt"):
        return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    # Built-in lightweight signed JWT implementation
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64encode(json.dumps(header).encode("utf-8"))
    payload_b64 = _b64encode(json.dumps(payload).encode("utf-8"))
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        f"{header_b64}.{payload_b64}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[str]:
    """Return the subject (username) from a valid token, or None if invalid or expired."""
    try:
        if _jwt_lib in ("jose", "pyjwt"):
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload.get("sub")

        # Custom verification
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode("utf-8"),
            f"{header_b64}.{payload_b64}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(sig_b64, _b64encode(expected_sig)):
            return None

        payload = json.loads(_b64decode(payload_b64).decode("utf-8"))
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            return None
        return payload.get("sub")
    except Exception:
        return None
