from fastapi import FastAPI
from backend_api.routers import user_accounts

app = FastAPI()

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/hello")
def hello():
    return {"message": "Hello from RASD"}


app.include_router(
    user_accounts.router,
    prefix="/me",
    tags=["user-accounts"]
)
