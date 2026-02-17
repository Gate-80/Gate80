
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from backend_api.routers import (
    admin_authentication,
    admin_operations,
    user_accounts,
    wallet,
    user_authentication
)
from backend_api.db.database import init_db

app = FastAPI(title="RASD Digital Wallet API", version="1.0.0")


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
    # Only allow health check (for monitoring/debugging)
    if request.url.path == "/health":
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