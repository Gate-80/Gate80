from fastapi import FastAPI
from backend_api.routers import admin_authentication, admin_operations, user_accounts, wallet

app = FastAPI()

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