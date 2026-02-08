from fastapi import APIRouter
router= APIRouter()


@router.post("/bank-accounts/update")
def update_bank_account():
    return {"message": "update bank account"}