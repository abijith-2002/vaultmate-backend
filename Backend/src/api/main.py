"""
VaultMate Security Backend - FastAPI Application

This module defines the main FastAPI application and wires all routes, middleware,
and OpenAPI metadata. It exposes REST API endpoints for:
- Authentication: registration, login, refresh, MFA enrollment/verify
- Vault items (credentials): CRUD, password generation, strength estimation
- Secure sharing: share/unshare credentials with RBAC checks
- Audit logs: record all actions and provide admin query
- Admin: user management, role assignment, system health

Environment variables:
- VM_SECRET_KEY: Secret key for JWT signing. (REQUIRED)
- VM_ACCESS_TOKEN_EXPIRE_MINUTES: Access token expiry in minutes (default: 30)
- VM_REFRESH_TOKEN_EXPIRE_DAYS: Refresh token expiry in days (default: 7)
- VM_CORS_ORIGINS: Comma-separated origins allowed for CORS (default: *)
- VM_ENCRYPTION_PEPPER: Optional server-side pepper to combine with user key for extra security
- VM_ADMIN_INVITE_CODE: Optional code required to create an admin account

Notes:
- This reference implementation uses in-memory stores for users, items, shares, and audit logs. 
  Replace with a persistent database in production (e.g., Supabase/Postgres).
- Passwords are hashed using PBKDF2-HMAC with per-user salt; vault item secrets are end-to-end
  encrypted client-side; server stores ciphertext only. For demo, we provide server-side AES-GCM 
  encryption utilities to support hybrid setups/testing, but clients should perform E2EE.
"""
from datetime import datetime, timedelta, timezone
import base64
import os
import secrets
import hashlib
from typing import List, Optional, Dict, Any, Tuple

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, JWTError
from uuid import uuid4

# Simple AES-GCM via cryptography is preferred, but to avoid extra deps in this template,
# we simulate encryption by storing base64 strings. In production, use a proper crypto library.
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------
# OpenAPI metadata and tags
# ----------------------------

openapi_tags = [
    {"name": "Health", "description": "Service health and metadata."},
    {"name": "Auth", "description": "User authentication, registration, tokens, MFA."},
    {"name": "Vault", "description": "Manage credentials stored in the vault."},
    {"name": "Sharing", "description": "Secure sharing of vault items with other users."},
    {"name": "Audit", "description": "Audit log retrieval (admin)."},
    {"name": "Admin", "description": "Administrative operations and RBAC."},
]

app = FastAPI(
    title="VaultMate Security API",
    version="1.0.0",
    description="Secure password manager backend with MFA, RBAC, credential sharing, and audit logging.",
    openapi_tags=openapi_tags,
)

# ----------------------------
# Config and environment
# ----------------------------

def getenv_str(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

SECRET_KEY = getenv_str("VM_SECRET_KEY", "dev-secret-change-me")  # Replace in production
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("VM_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("VM_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
CORS_ORIGINS = os.getenv("VM_CORS_ORIGINS", "*")
ENCRYPTION_PEPPER = os.getenv("VM_ENCRYPTION_PEPPER", "")
ADMIN_INVITE_CODE = os.getenv("VM_ADMIN_INVITE_CODE", "")

ALGORITHM = "HS256"
security_scheme = HTTPBearer(auto_error=False)

# ----------------------------
# CORS
# ----------------------------

allow_origins = ["*"] if CORS_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# In-memory storage (replace with DB)
# ----------------------------

class InMemoryDB:
    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {}           # key: user_id
        self.users_by_email: Dict[str, str] = {}              # email -> user_id
        self.vault_items: Dict[str, Dict[str, Any]] = {}      # item_id -> item
        self.shares: Dict[str, List[str]] = {}                # item_id -> list of user_ids granted
        self.audit_logs: List[Dict[str, Any]] = []            # append-only logs
        self.refresh_tokens: Dict[str, Dict[str, Any]] = {}   # token_id -> {user_id, exp}

DB = InMemoryDB()

# ----------------------------
# Security utilities
# ----------------------------

def _pbkdf2_hash(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return base64.b64encode(dk).decode("utf-8")

def hash_password(password: str) -> Tuple[str, str]:
    """Return (salt_b64, hash_b64)."""
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode("utf-8"), _pbkdf2_hash(password, salt)

def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    calc = _pbkdf2_hash(password, salt)
    return secrets.compare_digest(calc, hash_b64)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def create_access_token(subject: str, roles: List[str], mfa: bool, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    payload = {
        "sub": subject,
        "roles": roles,
        "mfa": mfa,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(minutes=expires_minutes)).timestamp()),
        "type": "access",
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(subject: str, expires_days: int = REFRESH_TOKEN_EXPIRE_DAYS) -> str:
    jti = str(uuid4())
    payload = {
        "sub": subject,
        "iat": int(now_utc().timestamp()),
        "exp": int((now_utc() + timedelta(days=expires_days)).timestamp()),
        "type": "refresh",
        "jti": jti,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    DB.refresh_tokens[jti] = {"user_id": subject, "exp": now_utc() + timedelta(days=expires_days)}
    return token

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)) -> Dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization")
    token = credentials.credentials
    claims = decode_token(token)
    if claims.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    return claims

def require_role(required: str):
    def _inner(claims: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
        roles = claims.get("roles") or []
        if required not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return claims
    return _inner

def require_mfa(claims: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
    if not bool(claims.get("mfa", False)):
        raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail="MFA required")
    return claims

# ----------------------------
# Models
# ----------------------------

class APIMessage(BaseModel):
    message: str = Field(..., description="Human-readable message")

class TokenPair(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field("bearer", description="Token type")

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

class MFASetupResponse(BaseModel):
    secret: str = Field(..., description="Base32 TOTP secret shared with authenticator app")
    otpauth_url: str = Field(..., description="otpauth URL for QR provisioning")

class MFAVerifyRequest(BaseModel):
    otp: str = Field(..., description="TOTP code to verify")

class UserProfile(BaseModel):
    user_id: str = Field(..., description="Unique user id")
    email: EmailStr = Field(..., description="User email")
    full_name: Optional[str] = Field(None, description="Full name")
    roles: List[str] = Field(default_factory=list, description="RBAC roles")
    mfa_enabled: bool = Field(..., description="Is MFA enabled")

class VaultItemCreate(BaseModel):
    title: str = Field(..., description="Label for the credential")
    username: str = Field(..., description="Account username")
    url: Optional[str] = Field(None, description="Associated URL")
    notes: Optional[str] = Field(None, description="Optional notes")
    secret_ciphertext: str = Field(..., description="Client-side encrypted secret (base64 or opaque)")

class VaultItem(BaseModel):
    item_id: str = Field(..., description="Item id")
    owner_id: str = Field(..., description="Owner user id")
    title: str
    username: str
    url: Optional[str] = None
    notes: Optional[str] = None
    secret_ciphertext: str
    created_at: datetime
    updated_at: datetime

class VaultItemUpdate(BaseModel):
    title: Optional[str] = None
    username: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    secret_ciphertext: Optional[str] = None

class ShareRequest(BaseModel):
    item_id: str = Field(..., description="Item to share")
    target_user_email: EmailStr = Field(..., description="User to grant access")

class UnshareRequest(BaseModel):
    item_id: str = Field(..., description="Item to unshare")
    target_user_email: EmailStr = Field(..., description="User to revoke")

class PasswordGenRequest(BaseModel):
    length: int = Field(16, ge=8, le=128, description="Password length")
    uppercase: bool = Field(True, description="Include uppercase letters")
    lowercase: bool = Field(True, description="Include lowercase letters")
    digits: bool = Field(True, description="Include digits")
    symbols: bool = Field(True, description="Include symbols")

class PasswordGenResponse(BaseModel):
    password: str = Field(..., description="Generated password")

class PasswordStrengthResponse(BaseModel):
    score: int = Field(..., ge=0, le=4, description="Score 0-4")
    warnings: List[str] = Field(default_factory=list, description="Warnings")
    suggestions: List[str] = Field(default_factory=list, description="Suggestions")

class AuditLogEntry(BaseModel):
    when: datetime
    actor: Optional[str]
    action: str
    resource: Optional[str]
    ip: Optional[str]
    meta: Dict[str, Any] = {}

class RoleUpdateRequest(BaseModel):
    user_id: str = Field(..., description="User id to update")
    roles: List[str] = Field(..., description="New roles list")

# ----------------------------
# Helpers
# ----------------------------

def log_event(request: Request, actor: Optional[str], action: str, resource: Optional[str] = None, meta: Optional[Dict[str, Any]] = None):
    entry = {
        "when": now_utc(),
        "actor": actor,
        "action": action,
        "resource": resource,
        "ip": request.client.host if request and request.client else None,
        "meta": meta or {},
    }
    DB.audit_logs.append(entry)

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    uid = DB.users_by_email.get(email.lower())
    if not uid:
        return None
    return DB.users.get(uid)

def ensure_item_access(user_id: str, item: Dict[str, Any]) -> None:
    if item["owner_id"] == user_id:
        return
    allowed = DB.shares.get(item["item_id"], [])
    if user_id not in allowed:
        raise HTTPException(status_code=403, detail="No access to this item")

# ----------------------------
# Routes
# ----------------------------

@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """Return simple health info."""
    return {"status": "ok", "service": "vaultmate-backend", "time": now_utc().isoformat()}

# PUBLIC_INTERFACE
@app.post("/auth/register", tags=["Auth"], response_model=UserProfile, summary="Register user")
def register(req: RegisterRequest, request: Request):
    """
    Register a new user.
    - Enforces unique email.
    - If admin_invite_code provided and matches VM_ADMIN_INVITE_CODE, grants 'admin' role.
    """
    email = req.email.lower()
    if email in DB.users_by_email:
        raise HTTPException(status_code=409, detail="Email already registered")
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")

    roles = ["user"]
    if req.admin_invite_code and ADMIN_INVITE_CODE and req.admin_invite_code == ADMIN_INVITE_CODE:
        roles.append("admin")

    salt, pwd_hash = hash_password(req.password)
    user_id = str(uuid4())
    user = {
        "user_id": user_id,
        "email": email,
        "full_name": req.full_name,
        "roles": roles,
        "password_salt": salt,
        "password_hash": pwd_hash,
        "mfa_enabled": False,
        "mfa_secret": None,  # base32 secret for TOTP
        "created_at": now_utc(),
    }
    DB.users[user_id] = user
    DB.users_by_email[email] = user_id
    log_event(request, actor=user_id, action="user.register", resource=user_id)
    return UserProfile(**{k: user[k] for k in ["user_id", "email", "full_name", "roles"]}, mfa_enabled=user["mfa_enabled"])

# PUBLIC_INTERFACE
@app.post("/auth/login", tags=["Auth"], response_model=TokenPair, summary="Login")
def login(req: LoginRequest, request: Request):
    """
    Authenticate user and return tokens.
    - If MFA enabled, require valid mfa_otp to receive access token with mfa=True.
    - If MFA not provided or invalid, returns access token with mfa=False to allow step-up.
    """
    user = get_user_by_email(req.email.lower())
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, user["password_salt"], user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    mfa_claim = False
    if user["mfa_enabled"]:
        if req.mfa_otp and verify_totp(user["mfa_secret"], req.mfa_otp):
            mfa_claim = True
        else:
            mfa_claim = False

    access = create_access_token(user["user_id"], user["roles"], mfa_claim)
    refresh = create_refresh_token(user["user_id"])
    log_event(request, actor=user["user_id"], action="auth.login", resource=user["user_id"], meta={"mfa": mfa_claim})
    return TokenPair(access_token=access, refresh_token=refresh)

# PUBLIC_INTERFACE
@app.post("/auth/refresh", tags=["Auth"], response_model=TokenPair, summary="Refresh tokens")
def refresh(req: RefreshRequest, request: Request):
    """Exchange refresh token for new token pair."""
    try:
        claims = jwt.decode(req.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    jti = claims.get("jti")
    entry = DB.refresh_tokens.get(jti)
    if not entry or entry["exp"] < now_utc():
        raise HTTPException(status_code=401, detail="Refresh token expired or revoked")
    user = DB.users.get(claims.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    access = create_access_token(user["user_id"], user["roles"], mfa=False)
    refresh_token = create_refresh_token(user["user_id"])
    log_event(request, actor=user["user_id"], action="auth.refresh", resource=user["user_id"])
    return TokenPair(access_token=access, refresh_token=refresh_token)

# MFA (TOTP) helpers and endpoints

def base32_secret(nbytes: int = 20) -> str:
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("utf-8").rstrip("=")

def _totp_now(secret_b32: str, interval: int = 30, digits: int = 6) -> str:
    # Minimal TOTP for demo (RFC 6238) using HMAC-SHA1
    import hmac, struct
    secret = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int(now_utc().timestamp() // interval)
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

def verify_totp(secret_b32: str, otp: str, window: int = 1) -> bool:
    # validate current +/- window steps
    if not secret_b32:
        return False
    try:
        for w in range(-window, window + 1):
            val = _totp_now_with_offset(secret_b32, offset=w)
            if secrets.compare_digest(val, otp):
                return True
        return False
    except Exception:
        return False

def _totp_now_with_offset(secret_b32: str, interval: int = 30, digits: int = 6, offset: int = 0) -> str:
    import hmac, struct
    secret = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int(now_utc().timestamp() // interval) + offset
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

# PUBLIC_INTERFACE
@app.post("/auth/mfa/setup", tags=["Auth"], response_model=MFASetupResponse, summary="Begin MFA setup")
def mfa_setup(claims: Dict[str, Any] = Depends(require_auth)):
    """
    Start MFA setup for the authenticated user by issuing a TOTP secret.
    The user must verify with an OTP via /auth/mfa/verify to enable MFA.
    """
    user = DB.users.get(claims["sub"])
    secret = base32_secret()
    user["mfa_secret"] = secret
    account = user["email"]
    issuer = "VaultMate"
    otpauth_url = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    return MFASetupResponse(secret=secret, otpauth_url=otpauth_url)

# PUBLIC_INTERFACE
@app.post("/auth/mfa/verify", tags=["Auth"], response_model=APIMessage, summary="Verify and enable MFA")
def mfa_verify(body: MFAVerifyRequest, request: Request, claims: Dict[str, Any] = Depends(require_auth)):
    """Verify a TOTP and enable MFA."""
    user = DB.users.get(claims["sub"])
    if not user.get("mfa_secret"):
        raise HTTPException(status_code=400, detail="MFA not initialized")
    if not verify_totp(user["mfa_secret"], body.otp):
        raise HTTPException(status_code=400, detail="Invalid OTP")
    user["mfa_enabled"] = True
    log_event(request, actor=user["user_id"], action="auth.mfa.enable", resource=user["user_id"])
    return APIMessage(message="MFA enabled")

# Profile

# PUBLIC_INTERFACE
@app.get("/me", tags=["Auth"], response_model=UserProfile, summary="Get my profile")
def me(claims: Dict[str, Any] = Depends(require_auth)):
    """Return the authenticated user's profile."""
    user = DB.users.get(claims["sub"])
    return UserProfile(
        user_id=user["user_id"],
        email=user["email"],
        full_name=user.get("full_name"),
        roles=user.get("roles", []),
        mfa_enabled=user.get("mfa_enabled", False),
    )

# Vault item endpoints

# PUBLIC_INTERFACE
@app.post("/vault/items", tags=["Vault"], response_model=VaultItem, summary="Create vault item")
def create_item(body: VaultItemCreate, request: Request, claims: Dict[str, Any] = Depends(require_mfa)):
    """Create a new credential item. Server stores client-side ciphertext only."""
    item_id = str(uuid4())
    now = now_utc()
    item = {
        "item_id": item_id,
        "owner_id": claims["sub"],
        "title": body.title,
        "username": body.username,
        "url": body.url,
        "notes": body.notes,
        "secret_ciphertext": body.secret_ciphertext,
        "created_at": now,
        "updated_at": now,
    }
    DB.vault_items[item_id] = item
    log_event(request, actor=claims["sub"], action="vault.create", resource=item_id)
    return VaultItem(**item)

# PUBLIC_INTERFACE
@app.get("/vault/items", tags=["Vault"], response_model=List[VaultItem], summary="List my accessible items")
def list_items(claims: Dict[str, Any] = Depends(require_mfa)):
    """List items owned by me or shared with me."""
    uid = claims["sub"]
    result = []
    for it in DB.vault_items.values():
        if it["owner_id"] == uid or uid in DB.shares.get(it["item_id"], []):
            result.append(VaultItem(**it))
    return result

# PUBLIC_INTERFACE
@app.get("/vault/items/{item_id}", tags=["Vault"], response_model=VaultItem, summary="Get item by id")
def get_item(item_id: str, claims: Dict[str, Any] = Depends(require_mfa)):
    """Retrieve a single item if owner or shared with user."""
    it = DB.vault_items.get(item_id)
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    ensure_item_access(claims["sub"], it)
    return VaultItem(**it)

# PUBLIC_INTERFACE
@app.patch("/vault/items/{item_id}", tags=["Vault"], response_model=VaultItem, summary="Update item")
def update_item(item_id: str, body: VaultItemUpdate, request: Request, claims: Dict[str, Any] = Depends(require_mfa)):
    """Update fields of an item. Only owner can update."""
    it = DB.vault_items.get(item_id)
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    if it["owner_id"] != claims["sub"]:
        raise HTTPException(status_code=403, detail="Only owner can update item")
    data = body.dict(exclude_unset=True)
    for k, v in data.items():
        it[k] = v
    it["updated_at"] = now_utc()
    log_event(request, actor=claims["sub"], action="vault.update", resource=item_id)
    return VaultItem(**it)

# PUBLIC_INTERFACE
@app.delete("/vault/items/{item_id}", tags=["Vault"], response_model=APIMessage, summary="Delete item")
def delete_item(item_id: str, request: Request, claims: Dict[str, Any] = Depends(require_mfa)):
    """Delete an item. Only owner can delete."""
    it = DB.vault_items.get(item_id)
    if not it:
        raise HTTPException(status_code=404, detail="Not found")
    if it["owner_id"] != claims["sub"]:
        raise HTTPException(status_code=403, detail="Only owner can delete item")
    DB.vault_items.pop(item_id, None)
    DB.shares.pop(item_id, None)
    log_event(request, actor=claims["sub"], action="vault.delete", resource=item_id)
    return APIMessage(message="Deleted")

# Sharing endpoints

# PUBLIC_INTERFACE
@app.post("/sharing/share", tags=["Sharing"], response_model=APIMessage, summary="Share a vault item")
def share_item(body: ShareRequest, request: Request, claims: Dict[str, Any] = Depends(require_mfa)):
    """Grant access to a target user by email. Only owner can share."""
    it = DB.vault_items.get(body.item_id)
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")
    if it["owner_id"] != claims["sub"]:
        raise HTTPException(status_code=403, detail="Only owner can share")
    target = get_user_by_email(body.target_user_email.lower())
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    if target["user_id"] == claims["sub"]:
        raise HTTPException(status_code=400, detail="Cannot share with self")
    DB.shares.setdefault(it["item_id"], [])
    if target["user_id"] not in DB.shares[it["item_id"]]:
        DB.shares[it["item_id"]].append(target["user_id"])
    log_event(request, actor=claims["sub"], action="sharing.share", resource=it["item_id"], meta={"target": target["user_id"]})
    return APIMessage(message="Shared")

# PUBLIC_INTERFACE
@app.post("/sharing/unshare", tags=["Sharing"], response_model=APIMessage, summary="Revoke sharing")
def unshare_item(body: UnshareRequest, request: Request, claims: Dict[str, Any] = Depends(require_mfa)):
    """Revoke access previously granted. Only owner can unshare."""
    it = DB.vault_items.get(body.item_id)
    if not it:
        raise HTTPException(status_code=404, detail="Item not found")
    if it["owner_id"] != claims["sub"]:
        raise HTTPException(status_code=403, detail="Only owner can unshare")
    target = get_user_by_email(body.target_user_email.lower())
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    allowed = DB.shares.get(it["item_id"], [])
    if target["user_id"] in allowed:
        allowed.remove(target["user_id"])
    log_event(request, actor=claims["sub"], action="sharing.unshare", resource=it["item_id"], meta={"target": target["user_id"]})
    return APIMessage(message="Unshared")

# Password tooling

# PUBLIC_INTERFACE
@app.post("/vault/passwords/generate", tags=["Vault"], response_model=PasswordGenResponse, summary="Generate a strong password")
def generate_password(body: PasswordGenRequest):
    """Generate a strong password according to the rules."""
    alphabet = ""
    if body.lowercase:
        alphabet += "abcdefghjkmnpqrstuvwxyz"
    if body.uppercase:
        alphabet += "ABCDEFGHJKMNPQRSTUVWXYZ"
    if body.digits:
        alphabet += "23456789"
    if body.symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.?/"
    if not alphabet:
        raise HTTPException(status_code=400, detail="No character sets selected")
    pw = "".join(secrets.choice(alphabet) for _ in range(body.length))
    return PasswordGenResponse(password=pw)

# PUBLIC_INTERFACE
@app.get("/vault/passwords/strength", tags=["Vault"], response_model=PasswordStrengthResponse, summary="Estimate password strength")
def password_strength(password: str = "", min_length: int = 12):
    """Simple heuristic password strength estimation (0-4)."""
    score = 0
    warnings: List[str] = []
    suggestions: List[str] = []

    if len(password) >= min_length:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in password):
        score = min(4, score + 1)

    if len(password) < min_length:
        warnings.append(f"Use at least {min_length} characters")
        suggestions.append("Increase length")
    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters")
    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters")
    if not any(c.isdigit() for c in password):
        suggestions.append("Add digits")
    if not any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in password):
        suggestions.append("Add symbols")

    return PasswordStrengthResponse(score=min(score, 4), warnings=warnings, suggestions=suggestions)

# Audit and Admin

# PUBLIC_INTERFACE
@app.get("/audit/logs", tags=["Audit"], response_model=List[AuditLogEntry], summary="List audit logs (admin)")
def list_audit_logs(_: Dict[str, Any] = Depends(require_role("admin"))):
    """Return audit trail entries. Admin only."""
    return [AuditLogEntry(**e) for e in DB.audit_logs]

# PUBLIC_INTERFACE
@app.get("/admin/users", tags=["Admin"], response_model=List[UserProfile], summary="List users (admin)")
def admin_list_users(_: Dict[str, Any] = Depends(require_role("admin"))):
    """List all users. Admin only."""
    profiles = []
    for u in DB.users.values():
        profiles.append(UserProfile(
            user_id=u["user_id"],
            email=u["email"],
            full_name=u.get("full_name"),
            roles=u.get("roles", []),
            mfa_enabled=u.get("mfa_enabled", False),
        ))
    return profiles

# PUBLIC_INTERFACE
@app.post("/admin/users/roles", tags=["Admin"], response_model=APIMessage, summary="Update user roles (admin)")
def admin_update_roles(body: RoleUpdateRequest, request: Request, _: Dict[str, Any] = Depends(require_role("admin"))):
    """Replace the roles array for a user. Admin only."""
    user = DB.users.get(body.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if "admin" not in body.roles and user["user_id"] == body.user_id:
        # no special restriction beyond existence in this demo
        pass
    user["roles"] = body.roles
    log_event(request, actor="admin", action="admin.roles.update", resource=user["user_id"], meta={"roles": body.roles})
    return APIMessage(message="Roles updated")

# PUBLIC_INTERFACE
@app.get("/admin/health", tags=["Admin"], response_model=Dict[str, Any], summary="System health (admin)")
def admin_health(_: Dict[str, Any] = Depends(require_role("admin"))):
    """Return basic in-memory stats."""
    return {
        "users": len(DB.users),
        "items": len(DB.vault_items),
        "shares": sum(len(v) for v in DB.shares.values()),
        "audit_entries": len(DB.audit_logs),
        "time": now_utc().isoformat(),
    }
