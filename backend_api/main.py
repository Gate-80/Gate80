
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend_api.routers import (
    admin_authentication,
    admin_operations,
    user_accounts,
    wallet,
    user_authentication,
    projects,
)
from backend_api.db.database import init_db
import backend_api.db.models
from backend_api.middleware.logging import RequestLoggingMiddleware
from backend_api.routers import onboarding
app = FastAPI(title="RASD Digital Wallet API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RequestLoggingMiddleware)


# Initialize database on startup
@app.on_event("startup")
def startup_event():
    """Initialize database tables on application startup"""
    init_db()
    print("✅ Database initialized")


# Middleware to block direct backend access (for proxy setup)
@app.middleware("http")
async def block_direct_backend_access(request: Request, call_next):
    """Block direct access to backend - requests must come through proxy"""
    # Allow health checks, browser preflight, and onboarding setup during local UI onboarding.
    if (
        request.method == "OPTIONS"
        or request.url.path == "/health"
        or request.url.path.startswith("/api/v1/onboarding")
        or request.url.path.startswith("/api/v1/auth")
        or request.url.path.startswith("/api/v1/projects")
    ):
        return await call_next(request)

    # Check for proxy header, all other requests must have proxy header
    if request.headers.get("X-From-Proxy") != "1":
        return JSONResponse(
            status_code=403,
            content={"detail": "Direct backend access forbidden. Use the API gateway."}
        )

    return await call_next(request)


# Health check endpoint
@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "digital-wallet-api"}


@app.get("/hello")
def hello():
    """Hello world endpoint"""
    return {"message": "Hello from RASD Digital Wallet API"}


# Include routers

app.include_router(
    onboarding.router,
    prefix="/api/v1",
    tags=["onboarding"]
)

app.include_router(
    projects.router,
    prefix="/api/v1",
    tags=["projects"]
)

app.include_router(
    user_authentication.router,
    prefix="/api/v1",
    tags=["user-authentication"]
)

app.include_router(
    user_accounts.router,
    prefix="/api/v1",
    tags=["user-accounts"]
)

app.include_router(
    wallet.router,
    prefix="/api/v1",
    tags=["wallet"]
)

app.include_router(
    admin_authentication.router,
    prefix="/api/v1",
    tags=["admin-authentication"]
)

app.include_router(
    admin_operations.router,
    prefix="/api/v1",
    tags=["admin-operations"]
)
