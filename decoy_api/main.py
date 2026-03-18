from fastapi import FastAPI
from decoy_api.routers import decoy_user_auth,decoy_useraccounts,decoy_wallet

app = FastAPI(title="Decoy API")

app.include_router(decoy_user_auth.router, prefix="/api/v1", tags=["auth"])
app.include_router(decoy_wallet.router, prefix="/api/v1", tags=["wallet"])
app.include_router(decoy_useraccounts.router, prefix="/api/v1", tags=["user-accounts"])