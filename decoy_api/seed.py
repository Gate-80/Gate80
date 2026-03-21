"""
GATE80 — Decoy API
seed.py

Seeds decoy_wallet.db with believable fake data on startup.
Only runs if the DB is empty — safe to call on every startup.
"""

import logging
from decoy_api.db.database import WalletSession
from decoy_api.db.models import (
    DecoyUser, DecoyWallet, DecoyTransaction, DecoyBankAccount,
    DecoyPayment, WalletStatus, TransactionType, TransactionStatus
)

logger = logging.getLogger("decoy.seed")


def seed():
    db = WalletSession()
    try:
        # Skip if already seeded
        if db.query(DecoyUser).count() > 0:
            logger.info("DECOY 🌱 DB already seeded — skipping")
            return

        logger.info("DECOY 🌱 Seeding decoy_wallet.db...")

        # ── Users ─────────────────────────────────────────────────────────────
        users = [
            DecoyUser(
                id="u_1004", full_name="Test User",
                email="user@example.com", password="password123",
                phone="+9665XXXXXXX", city="Jeddah", is_verified=True,
            ),
            DecoyUser(
                id="u_1002", full_name="Hanan Al-Harbi",
                email="hanan.alharbi@gmail.com", password="password123",
                phone="+9665XXXXXXX", city="Riyadh", is_verified=True,
            ),
            DecoyUser(
                id="u_1003", full_name="Taif Al-Saadi",
                email="taif.alsaadi@gmail.com", password="password123",
                phone="+9665XXXXXXX", city="Mecca", is_verified=True,
            ),
        ]
        for u in users:
            db.add(u)

        # ── Wallets ───────────────────────────────────────────────────────────
        wallets = [
            DecoyWallet(id="w_5001", user_id="u_1004",
                        currency_code="SAR", balance="4250.75",
                        status=WalletStatus.ACTIVE),
            DecoyWallet(id="w_5002", user_id="u_1002",
                        currency_code="SAR", balance="12800.00",
                        status=WalletStatus.ACTIVE),
            DecoyWallet(id="w_5003", user_id="u_1003",
                        currency_code="SAR", balance="650.50",
                        status=WalletStatus.ACTIVE),
        ]
        for w in wallets:
            db.add(w)

        # ── Transactions (history — makes it look lived-in) ───────────────────
        transactions = [
            DecoyTransaction(
                id="tx_7001", user_id="u_1004", wallet_id="w_5001",
                type=TransactionType.TOPUP, status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "1000.00"},
                counterparty={"kind": "CARD", "ref": "card_****_1234"},
                description="Top up via card",
            ),
            DecoyTransaction(
                id="tx_7002", user_id="u_1004", wallet_id="w_5001",
                type=TransactionType.TRANSFER_USER, status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "250.00"},
                counterparty={"kind": "USER", "ref": "u_1002"},
                description="Transfer to user u_1002",
            ),
            DecoyTransaction(
                id="tx_7003", user_id="u_1004", wallet_id="w_5001",
                type=TransactionType.BILLPAY, status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "180.00"},
                counterparty={"kind": "BILLER", "ref": "biller_stc"},
                description="STC bill payment",
            ),
            DecoyTransaction(
                id="tx_7004", user_id="u_1002", wallet_id="w_5002",
                type=TransactionType.TOPUP, status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "5000.00"},
                counterparty={"kind": "CARD", "ref": "card_****_5678"},
                description="Top up via card",
            ),
            DecoyTransaction(
                id="tx_7005", user_id="u_1003", wallet_id="w_5003",
                type=TransactionType.WITHDRAW, status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "200.00"},
                counterparty={"kind": "BANK", "ref": "ba_2003"},
                description="Withdraw to bank account",
            ),
        ]
        for t in transactions:
            db.add(t)

        # ── Bank Accounts ─────────────────────────────────────────────────────
        bank_accounts = [
            DecoyBankAccount(
                id="ba_2001", user_id="u_1004",
                bank_name="Al Rajhi Bank",
                iban="SA4420000001234567891299",
                masked_account_number="**** **** **** 1299",
                currency="SAR", is_default=True,
            ),
            DecoyBankAccount(
                id="ba_2002", user_id="u_1002",
                bank_name="Saudi National Bank",
                iban="SA3620000009876543210001",
                masked_account_number="**** **** **** 0001",
                currency="SAR", is_default=True,
            ),
            DecoyBankAccount(
                id="ba_2003", user_id="u_1003",
                bank_name="Riyad Bank",
                iban="SA1120000005678912340002",
                masked_account_number="**** **** **** 0002",
                currency="SAR", is_default=True,
            ),
        ]
        for b in bank_accounts:
            db.add(b)

        # ── Payments ──────────────────────────────────────────────────────────
        payments = [
            DecoyPayment(
                id="pay_3001", user_id="u_1004", status="COMPLETED",
                amount={"currency_code": "SAR", "value": "299.00"},
                merchant={"name": "Amazon Saudi", "merchant_id": "m_9001"},
                description="Order #A1001",
            ),
            DecoyPayment(
                id="pay_3002", user_id="u_1004", status="COMPLETED",
                amount={"currency_code": "SAR", "value": "85.50"},
                merchant={"name": "Jarir Bookstore", "merchant_id": "m_9002"},
                description="Books purchase",
            ),
            DecoyPayment(
                id="pay_3003", user_id="u_1002", status="COMPLETED",
                amount={"currency_code": "SAR", "value": "450.00"},
                merchant={"name": "STC", "merchant_id": "m_9003"},
                description="Monthly subscription",
            ),
        ]
        for p in payments:
            db.add(p)

        db.commit()
        logger.info("DECOY ✅ Seeded: 3 users, 3 wallets, 5 transactions, 3 bank accounts, 3 payments")

    except Exception as e:
        logger.error("DECOY ❌ Seeding failed: %s", e)
        db.rollback()
    finally:
        db.close()