from __future__ import annotations

import base64
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import hashlib
import hmac

from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

# --------------------------------------------------------------------------------------
# Models (Pydantic) aligned with the provided OpenAPI components
# --------------------------------------------------------------------------------------


class APIMessage(BaseModel):
    message: str = Field(..., description="Human-readable message")


class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=8, description="User password")
    full_name: Optional[str] = Field(None, description="Full name")
    admin_invite_code: Optional[str] = Field(None, description="Required for admin creation")


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., description="User password")
    mfa_otp: Optional[str] = Field(None, description="TOTP value if MFA is enabled")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


class TokenPair(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")


class UserProfile(BaseModel):
    user_id: str = Field(..., description="Unique user id")
    email: EmailStr = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="Full name")
    roles: List[str] = Field(default_factory=list, description="RBAC roles")
    mfa_enabled: bool = Field(..., description="Is MFA enabled")


class MFASetupResponse(BaseModel):
    secret: str = Field(..., description="Base32 TOTP secret shared with authenticator app")
    otpauth_url: str = Field(..., description="otpauth URL for QR provisioning")


class MFAVerifyRequest(BaseModel):
    otp: str = Field(..., description="TOTP code to verify")


# --------------------------------------------------------------------------------------
# In-memory "database" and helpers
# --------------------------------------------------------------------------------------


class InMemoryUser:
    def __init__(
        self,
        email: str,
        password_hash: str,
        full_name: Optional[str],
        roles: Optional[List[str]] = None,
    ):
        self.user_id: str = str(uuid.uuid4())
        self.email: str = email
        self.password_hash: str = password_hash
        self.full_name: Optional[str] = full_name
        self.roles: List[str] = roles or []
        self.mfa_enabled: bool = False
        self.mfa_secret_b32: Optional[str] = None


class MemoryStore:
    def __init__(self):
        self.users_by_email: Dict[str, InMemoryUser] = {}
        self.users_by_id: Dict[str, InMemoryUser] = {}
        # map refresh token -> (user_id, expiry_ts)
        self.refresh_index: Dict[str, Tuple[str, int]] = {}


STORE = MemoryStore()


def _hash_password(password: str) -> str:
    # Use a simple salted sha256 for MVP (not secure for prod)
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def _check_password(password: str, password_hash: str) -> bool:
    try:
        salt, digest = password_hash.split("$", 1)
    except ValueError:
        return False
    check = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(check, digest)


def _b32_secret(length: int = 20) -> str:
    # Generate base32 secret for TOTP
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("utf-8").replace("=", "")


def _totp_at(secret_b32: str, for_time: Optional[int] = None, step: int = 30, digits: int = 6) -> str:
    """
    Minimal TOTP (RFC 6238) implementation using HMAC-SHA1. MVP only.
    """
    if for_time is None:
        for_time = int(time.time())
    counter = int(for_time // step)
    key = base64.b32decode(secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8), casefold=True)
    msg = counter.to_bytes(8, "big")
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    dbc = int.from_bytes(mac[offset : offset + 4], "big") & 0x7FFFFFFF
    code = dbc % (10**digits)
    return str(code).zfill(digits)


def _verify_totp(secret_b32: str, otp: str, window: int = 1) -> bool:
    # allow time-drift window (prev, current, next)
    now = int(time.time())
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_totp_at(secret_b32, now + delta * 30), otp):
            return True
    return False


# --------------------------------------------------------------------------------------
# Token handling (MVP opaque tokens)
# --------------------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _encode_claims(claims: Dict) -> str:
    """
    MVP: not a real JWT. Base64-url encode the bytes to look opaque.
    """
    raw = str(claims).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def _decode_claims(token: str) -> Dict:
    try:
        data = base64.urlsafe_b64decode(token.encode("utf-8"))
        text = data.decode("utf-8")
        # eval is unsafe; in MVP, parse dict-like string safely
        # We'll parse a very restricted format produced above.
        # Fallback: return empty dict on parse error.
        result: Dict = {}
        # extremely naive parser for "{'k': 'v', 'n': 1}"
        text = text.strip()
        if text.startswith("{") and text.endswith("}"):
            inner = text[1:-1].strip()
            if inner:
                parts = []
                depth = 0
                current = ""
                for ch in inner:
                    if ch == "," and depth == 0:
                        parts.append(current.strip())
                        current = ""
                    else:
                        current += ch
                        if ch in "'\"":
                            depth ^= 1
                if current:
                    parts.append(current.strip())
                for p in parts:
                    if ":" not in p:
                        continue
                    k, v = p.split(":", 1)
                    key = k.strip().strip("'\"")
                    val = v.strip()
                    if val.startswith("'") and val.endswith("'"):
                        result[key] = val.strip("'")
                    elif val.startswith("\"") and val.endswith("\""):
                        result[key] = val.strip("\"")
                    elif val.lower() in ("true", "false"):
                        result[key] = val.lower() == "true"
                    else:
                        try:
                            result[key] = int(val)
                        except ValueError:
                            result[key] = val
        return result
    except Exception:
        return {}


def _new_access_token(user: InMemoryUser, mfa_ok: bool, ttl_minutes: int = 15) -> str:
    exp = int((_utcnow() + timedelta(minutes=ttl_minutes)).timestamp())
    claims = {
        "sub": user.user_id,
        "email": user.email,
        "roles": ",".join(user.roles),
        "mfa": str(mfa_ok),
        "exp": exp,
        "typ": "access",
        "iat": int(_utcnow().timestamp()),
        "jti": secrets.token_urlsafe(8),
    }
    return _encode_claims(claims)


def _new_refresh_token(user: InMemoryUser, ttl_days: int = 7) -> str:
    exp = int((_utcnow() + timedelta(days=ttl_days)).timestamp())
    token = secrets.token_urlsafe(32)
    STORE.refresh_index[token] = (user.user_id, exp)
    return token


def _validate_access_token(token: str) -> Optional[Dict]:
    claims = _decode_claims(token)
    if not claims:
        return None
    if claims.get("typ") != "access":
        return None
    exp = int(claims.get("exp", 0))
    if int(_utcnow().timestamp()) > exp:
        return None
    return claims


def _exchange_refresh(refresh_token: str) -> Tuple[Optional[InMemoryUser], Optional[str]]:
    meta = STORE.refresh_index.get(refresh_token)
    if not meta:
        return None, "invalid_refresh"
    user_id, exp = meta
    if int(_utcnow().timestamp()) > exp:
        # expired, remove
        STORE.refresh_index.pop(refresh_token, None)
        return None, "expired_refresh"
    user = STORE.users_by_id.get(user_id)
    if not user:
        return None, "user_not_found"
    return user, None


# --------------------------------------------------------------------------------------
# Security dependencies
# --------------------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)


# PUBLIC_INTERFACE
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> InMemoryUser:
    """
    Resolve and validate the bearer access token and return the current user.
    Raises HTTP 401 if token missing/invalid or user not found.
    """
    if credentials is None or not credentials.scheme.lower() == "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    claims = _validate_access_token(token)
    if not claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    user = STORE.users_by_id.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


router = APIRouter(prefix="", tags=["Auth"])


# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------


@router.post(
    "/auth/register",
    response_model=UserProfile,
    summary="Register user",
    description="Register a new user.\n- Enforces unique email.\n- If admin_invite_code provided and matches VM_ADMIN_INVITE_CODE, grants 'admin' role.",
)
def register(payload: RegisterRequest) -> UserProfile:
    """
    Register a new user in the in-memory store.

    Parameters:
    - email: required email
    - password: required password (min 8)
    - full_name: optional
    - admin_invite_code: optional; if matches env VM_ADMIN_INVITE_CODE, assigns 'admin' role

    Returns:
    - UserProfile
    """
    email_l = payload.email.lower()
    if email_l in STORE.users_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    # role assignment
    roles: List[str] = []
    expected_code = os.getenv("VM_ADMIN_INVITE_CODE", "")
    if payload.admin_invite_code and expected_code and secrets.compare_digest(payload.admin_invite_code, expected_code):
        roles.append("admin")

    user = InMemoryUser(
        email=email_l,
        password_hash=_hash_password(payload.password),
        full_name=payload.full_name,
        roles=roles,
    )
    STORE.users_by_email[email_l] = user
    STORE.users_by_id[user.user_id] = user

    return UserProfile(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        roles=user.roles,
        mfa_enabled=user.mfa_enabled,
    )


@router.post(
    "/auth/login",
    response_model=TokenPair,
    summary="Login",
    description="Authenticate user and return tokens.\n- If MFA enabled, require valid mfa_otp to receive access token with mfa=True.\n- If MFA not provided or invalid, returns access token with mfa=False to allow step-up.",
)
def login(payload: LoginRequest) -> TokenPair:
    """
    Authenticate a user with email and password. Issues token pair.

    - If user's MFA is enabled:
      - When valid mfa_otp provided, access token claim mfa=True.
      - When missing/invalid mfa_otp, access token claim mfa=False (allows step-up).
    - If user's MFA is not enabled: mfa=True in access token.

    Returns:
    - TokenPair
    """
    user = STORE.users_by_email.get(payload.email.lower())
    if not user or not _check_password(payload.password, user.password_hash):
        # Use same error for both to avoid leaking info
        raise HTTPException(status_code=401, detail="Invalid credentials")

    mfa_ok = True
    if user.mfa_enabled:
        # Require mfa_otp for mfa_ok=True
        mfa_ok = False
        if payload.mfa_otp and user.mfa_secret_b32 and _verify_totp(user.mfa_secret_b32, payload.mfa_otp):
            mfa_ok = True

    access = _new_access_token(user, mfa_ok=mfa_ok)
    refresh = _new_refresh_token(user)
    return TokenPair(access_token=access, refresh_token=refresh, token_type="bearer")


@router.post(
    "/auth/refresh",
    response_model=TokenPair,
    summary="Refresh tokens",
    description="Exchange refresh token for new token pair.",
)
def refresh(payload: RefreshRequest) -> TokenPair:
    """
    Exchange refresh token for a new token pair.

    Returns:
    - TokenPair
    """
    user, err = _exchange_refresh(payload.refresh_token)
    if err or not user:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    # Note: New access is issued with mfa=True if user's MFA disabled; otherwise False to enforce step-up on new session.
    mfa_ok = not user.mfa_enabled
    access = _new_access_token(user, mfa_ok=mfa_ok)
    refresh_token = _new_refresh_token(user)
    return TokenPair(access_token=access, refresh_token=refresh_token, token_type="bearer")


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get my profile",
    description="Return the authenticated user's profile.",
)
def me(current: InMemoryUser = Depends(get_current_user)) -> UserProfile:
    """
    Return the authenticated user's profile.

    Security:
    - Requires Bearer access token.

    Returns:
    - UserProfile
    """
    return UserProfile(
        user_id=current.user_id,
        email=current.email,
        full_name=current.full_name,
        roles=current.roles,
        mfa_enabled=current.mfa_enabled,
    )


@router.post(
    "/auth/mfa/setup",
    response_model=MFASetupResponse,
    summary="Begin MFA setup",
    description=(
        "Start MFA setup for the authenticated user by issuing a TOTP secret.\n"
        "The user must verify with an OTP via /auth/mfa/verify to enable MFA."
    ),
)
def mfa_setup(current: InMemoryUser = Depends(get_current_user)) -> MFASetupResponse:
    """
    Begin MFA setup by generating a TOTP secret and returning an otpauth URL.

    Returns:
    - MFASetupResponse: secret and otpauth URL
    """
    secret_b32 = _b32_secret()
    current.mfa_secret_b32 = secret_b32
    # Construct otpauth URL (issuer VaultMate, account = email)
    issuer = "VaultMate"
    label = f"{issuer}:{current.email}"
    otpauth = f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    return MFASetupResponse(secret=secret_b32, otpauth_url=otpauth)


@router.post(
    "/auth/mfa/verify",
    response_model=APIMessage,
    summary="Verify and enable MFA",
    description="Verify a TOTP and enable MFA.",
)
def mfa_verify(payload: MFAVerifyRequest, current: InMemoryUser = Depends(get_current_user)) -> APIMessage:
    """
    Verify the provided TOTP and enable MFA if valid.

    Returns:
    - APIMessage
    """
    if not current.mfa_secret_b32:
        raise HTTPException(status_code=400, detail="MFA setup not initiated")
    if not _verify_totp(current.mfa_secret_b32, payload.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    current.mfa_enabled = True
    return APIMessage(message="MFA enabled")
