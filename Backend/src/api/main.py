from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import router as auth_router

app = FastAPI(
    title="VaultMate Security API",
    description="Secure password manager backend with MFA, RBAC, credential sharing, and audit logging.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Health", "description": "Service health and metadata."},
        {"name": "Auth", "description": "User authentication, registration, tokens, MFA."},
        {"name": "Vault", "description": "Manage credentials stored in the vault."},
        {"name": "Sharing", "description": "Secure sharing of vault items with other users."},
        {"name": "Audit", "description": "Audit log retrieval (admin)."},
        {"name": "Admin", "description": "Administrative operations and RBAC."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Health"], summary="Health Check", description="Return simple health info.")
def health_check():
    """Health check endpoint returning minimal service status."""
    return {"message": "Healthy"}


# Register routers
app.include_router(auth_router)
