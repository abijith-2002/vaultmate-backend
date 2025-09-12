from __future__ import annotations

import os
from typing import List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

# Supabase configuration
# Note: Ensure the following environment variables are set via .env (do not hardcode):
# - SUPABASE_URL
# - SUPABASE_ANON_KEY
# - VM_ADMIN_INVITE_CODE (optional, used only for tagging admin role locally)
SUPABASE_URL = os.getenv("SUPABASE_URL")  # e.g., https://your-project.supabase.co
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")  # service/anon key provided by env

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    # We don't raise at import time to allow docs to load, but endpoints will validate.
    pass


# --------------------------------------------------------------------------------------
# Models (Pydantic) aligned with OpenAPI components (MFA removed)
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


bearer_scheme = HTTPBearer(auto_error=False)
router = APIRouter(prefix="", tags=["Auth"])


async def _assert_supabase_config():
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise HTTPException(
            status_code=500,
            detail="Supabase configuration missing. Ensure SUPABASE_URL and SUPABASE_ANON_KEY are set.",
        )


async def _supabase_post(client: httpx.AsyncClient, path: str, json: dict) -> dict:
    """
    Helper to call Supabase Auth endpoints.
    """
    headers = {
        "apikey": SUPABASE_ANON_KEY or "",
        "Authorization": f"Bearer {SUPABASE_ANON_KEY or ''}",
        "Content-Type": "application/json",
    }
    url = f"{SUPABASE_URL}/auth/v1{path}"
    resp = await client.post(url, headers=headers, json=json)
    if resp.status_code >= 400:
        try:
            err = resp.json()
        except Exception:
            err = {"error": resp.text}
        raise HTTPException(status_code=resp.status_code, detail=err)
    return resp.json()


async def _supabase_get_user(client: httpx.AsyncClient, access_token: str) -> dict:
    headers = {
        "apikey": SUPABASE_ANON_KEY or "",
        "Authorization": f"Bearer {access_token}",
    }
    url = f"{SUPABASE_URL}/auth/v1/user"
    resp = await client.get(url, headers=headers)
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    return resp.json()


# PUBLIC_INTERFACE
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
) -> UserProfile:
    """
    Resolve and validate the Supabase bearer access token and return the current user profile.

    Security:
    - Requires bearer token obtained from Supabase sign-in/sign-up.

    Returns:
    - UserProfile with roles derived from user_metadata 'roles' if present.
    """
    await _assert_supabase_config()
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    token = credentials.credentials
    async with httpx.AsyncClient(timeout=10) as client:
        user_data = await _supabase_get_user(client, token)

    # Map Supabase user to our UserProfile shape
    uid = user_data.get("id") or user_data.get("user", {}).get("id")
    email = user_data.get("email") or user_data.get("user", {}).get("email")
    user_metadata = user_data.get("user_metadata") or {}
    roles = user_metadata.get("roles") or []
    full_name = user_metadata.get("full_name") or None
    if isinstance(roles, str):
        roles = [roles]
    if not uid or not email:
        raise HTTPException(status_code=401, detail="Invalid user payload from auth provider")
    return UserProfile(user_id=uid, email=email, full_name=full_name, roles=roles)


@router.post(
    "/auth/register",
    response_model=UserProfile,
    summary="Register user",
    description="Register a new user via Supabase Auth. If admin_invite_code matches VM_ADMIN_INVITE_CODE, add 'admin' to metadata roles.",
)
async def register(payload: RegisterRequest) -> UserProfile:
    """
    Register a new user using Supabase Auth.

    Notes:
    - The backend delegates user creation to Supabase (email/password auth).
    - If VM_ADMIN_INVITE_CODE matches, we set initial roles metadata to include 'admin'.
    - emailRedirectTo should be configured on the frontend; backend doesn't send confirm links here.

    Returns:
    - UserProfile (derived from Supabase user object)
    """
    await _assert_supabase_config()

    # Prepare user metadata
    roles: List[str] = []
    expected_code = os.getenv("VM_ADMIN_INVITE_CODE", "")
    if payload.admin_invite_code and expected_code and payload.admin_invite_code == expected_code:
        roles.append("admin")

    user_metadata = {"full_name": payload.full_name} if payload.full_name else {}
    if roles:
        user_metadata["roles"] = roles

    async with httpx.AsyncClient(timeout=10) as client:
        # Supabase sign up
        data = await _supabase_post(
            client,
            "/signup",
            {
                "email": str(payload.email),
                "password": payload.password,
                "data": user_metadata,
            },
        )

        # If email confirmation is enabled, Supabase may return user or session depending on config.
        user = data.get("user") or data
        uid = user.get("id")
        email = user.get("email")
        u_meta = user.get("user_metadata") or {}
        full_name = u_meta.get("full_name")
        ret_roles = u_meta.get("roles") or []
        if isinstance(ret_roles, str):
            ret_roles = [ret_roles]

        if not uid or not email:
            raise HTTPException(status_code=500, detail="Unexpected response from auth provider")

        return UserProfile(user_id=uid, email=email, full_name=full_name, roles=ret_roles)


@router.post(
    "/auth/login",
    response_model=TokenPair,
    summary="Login",
    description="Authenticate user via Supabase and return tokens.",
)
async def login(payload: LoginRequest) -> TokenPair:
    """
    Login via Supabase email/password.

    Returns:
    - TokenPair with access_token and refresh_token from Supabase.
    """
    await _assert_supabase_config()
    async with httpx.AsyncClient(timeout=10) as client:
        data = await _supabase_post(
            client,
            "/token?grant_type=password",
            {
                "email": str(payload.email),
                "password": payload.password,
            },
        )

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Authentication failed")

    return TokenPair(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post(
    "/auth/refresh",
    response_model=TokenPair,
    summary="Refresh tokens",
    description="Exchange refresh token for new token pair using Supabase.",
)
async def refresh(payload: RefreshRequest) -> TokenPair:
    """
    Use Supabase refresh token to obtain new access and refresh tokens.

    Returns:
    - TokenPair
    """
    await _assert_supabase_config()
    async with httpx.AsyncClient(timeout=10) as client:
        data = await _supabase_post(
            client,
            "/token?grant_type=refresh_token",
            {
                "refresh_token": payload.refresh_token,
            },
        )

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    return TokenPair(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get my profile",
    description="Return the authenticated user's profile obtained from Supabase.",
)
async def me(current: UserProfile = Depends(get_current_user)) -> UserProfile:
    """
    Return the authenticated user's profile.

    Security:
    - Requires Supabase Bearer access token.

    Returns:
    - UserProfile
    """
    return current
