from backend_api.routers.user_accounts import T_USERS, T_BANK_ACCOUNTS, now_iso
from pydantic import BaseModel, condecimal
from fastapi import APIRouter, HTTPException, Query

router = APIRouter(tags=["Wallet"])
T_WALLETS = {
    "u_1001": {"balance": 5000.00, "currency": "SAR"},
    "u_1002": {"balance": 2500.00, "currency": "SAR"},
    "u_1003": {"balance": 10000.00,"currency":"SAR"},
}

T_TRANSACTIONS = []

class WalletBalanceResponse(BaseModel):
    user_id: str
    balance: float
    currency: str

class WalletAmountRequest(BaseModel):
    amount: condecimal(max_digits=10, decimal_places=2)


@router.get("/users/{user_id}/wallet", response_model=WalletBalanceResponse)
def view_wallet_balance(user_id: str):
    wallet = T_WALLETS.get(user_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return {
        "user_id": user_id,
        "balance": wallet["balance"],
        "currency": wallet["currency"],
    }
    
@router.post("/users/{user_id}/wallet/topup")
def topup_wallet(user_id: str, payload: WalletAmountRequest):
    wallet = T_WALLETS.get(user_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")

    wallet["balance"] += float(payload.amount)

    T_TRANSACTIONS.append({
        "id": f"tx_{len(T_TRANSACTIONS)+1}",
        "user_id": user_id,
        "type": "TOPUP",
        "amount": str(payload.amount),
        "created_at": now_iso()
    })

    return {"message": "Wallet topped up", "new_balance": wallet["balance"]+"SAR"}

@router.post("/users/{user_id}/wallet/withdrawl")
def withdrawl(user_id:str, payload:WalletAmountRequest):
    wallet=T_WALLETS.get(user_id)
    if not wallet:
       raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet["balance"] < float(payload.amount):
        raise HTTPException(status_code=400, detail="Insufficient balance")

    wallet["balance"] -=  float(payload.amount)

    T_TRANSACTIONS.append({
        "id": f"tx_{len(T_TRANSACTIONS)+1}",
        "user_id": user_id,
        "type": "WITHDRAW",
        "amount": str(payload.amount),
        "created_at": now_iso()
    })

    return {"message": "Withdraw successful", "new_balance": wallet["balance"]+"SAR"}

@router.post("/users/{user_id}/wallet/transfer/{target_user_id}")
def transfer_to_user(user_id: str, target_user_id: str, payload: WalletAmountRequest):
    sender_wallet = T_WALLETS.get(user_id)
    receiver_wallet = T_WALLETS.get(target_user_id)

    if not sender_wallet or not receiver_wallet:
        raise HTTPException(status_code=404, detail="User wallet not found")

    if sender_wallet["balance"] < float(payload.amount):
        raise HTTPException(status_code=400, detail="Insufficient balance")

    sender_wallet["balance"] -= float(payload.amount)
    receiver_wallet["balance"] += float(payload.amount)

    T_TRANSACTIONS.append({
        "id": f"tx_{len(T_TRANSACTIONS)+1}",
        "user_id": user_id,
        "type": "TRANSFER",
        "amount": str(payload.amount),
        "to": target_user_id,
        "created_at": now_iso()
    })

    return {"message": "Transfer successful", "new_balance": sender_wallet["balance"]}
    
@router.post("/users/{user_id}/wallet/pay-bill")
def pay_bill(user_id: str, payload: WalletAmountRequest):
    wallet = T_WALLETS.get(user_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")

    if wallet["balance"] < float(payload.amount):
        raise HTTPException(status_code=400, detail="Insufficient balance")

    wallet["balance"] -= float(payload.amount)

    T_TRANSACTIONS.append({
        "id": f"tx_{len(T_TRANSACTIONS)+1}",
        "user_id": user_id,
        "type": "BILL_PAYMENT",
        "amount": str(payload.amount),
        "created_at": now_iso()
    })

    return {"message": "Bill paid successfully", "new_balance": wallet["balance"]}
