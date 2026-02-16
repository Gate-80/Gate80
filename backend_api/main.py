from fastapi import FastAPI, Request, HTTPException
from backend_api.routers import admin_authentication, admin_operations, user_accounts, wallet, user_authentication
from fastapi.responses import JSONResponse

app = FastAPI()

from fastapi import FastAPI, Request, HTTPException
from backend_api.routers import admin_authentication, admin_operations, user_accounts, wallet, user_authentication

app = FastAPI()

@app.middleware("http")
async def block_direct_backend_access(request: Request, call_next):
    if request.url.path in ("/health", "/docs", "/openapi.json"):
        return await call_next(request)

    if request.headers.get("X-From-Proxy") != "1":
         return JSONResponse(
            status_code=403,
            content={"detail": "Direct backend access blocked"}
        )


    return await call_next(request)


@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/hello")
def hello():
    return {"message": "Hello from RASD"}


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
   admin_operations.router,
    prefix="/api/v1",
    tags=["admin-operations"]

)
app.include_router(
    admin_authentication.router,
    prefix="/api/v1",
    tags=["admin-authentication"]
)

app.include_router(
    user_authentication.router,
    prefix="/api/v1",
    tags=["user-authentication"]
)
