# Initial data for testing

"""
Seed script to populate the database with initial test data.
Run this once after creating the database tables.
"""

from sqlalchemy.orm import Session
from backend_api.db.database import SessionLocal, init_db
from backend_api.db.models import (
    User, BankAccount, Wallet, Transaction, Payment, Admin,
    TransactionStatus, TransactionType, PaymentStatus, WalletStatus
)
from datetime import datetime, timezone


def seed_database():
    """Populate database with initial test data"""
    
    # Initialize database (create tables)
    print("Creating database tables...")
    init_db()
    
    # Create database session
    db = SessionLocal()
    
    try:
        # Check if data already exists
        if db.query(User).count() > 0:
            print("Database already has data. Skipping seed.")
            return
        
        print("Seeding database with test data...")
        
        # -------------------------
        # Create Users
        # -------------------------
        users = [
            User(
                id="u_1001",
                full_name="Taif Alsaadi",
                email="taif.alsaadi@gmail.com",
                password="password123",  # In production: hash this
                phone="+9665XXXXXXX",
                city="Jeddah",
                is_verified=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
            User(
                id="u_1002",
                full_name="Hanan Alharbi",
                email="hanan.alharbi@gmail.com",
                password="password123",
                phone="+9665XXXXXXX",
                city="Riyadh",
                is_verified=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
            User(
                id="u_1003",
                full_name="Queen RAMA",
                email="queenrama@gmail.com",
                password="imthequ33n",
                phone="+9665XXXXXXX",
                city="New York",
                is_verified=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(users)
        print(f"✓ Created {len(users)} users")
        
        # -------------------------
        # Create Bank Accounts
        # -------------------------
        bank_accounts = [
            BankAccount(
                id="ba_2001",
                user_id="u_1001",
                bank_name="Al Rajhi Bank",
                iban="SA4420000001234567891234",
                masked_account_number="**** **** **** 3192",
                currency="SAR",
                is_default=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
            BankAccount(
                id="ba_2002",
                user_id="u_1002",
                bank_name="Saudi National Bank",
                iban="SA1520000009876543219876",
                masked_account_number="**** **** **** 7741",
                currency="SAR",
                is_default=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
            BankAccount(
                id="ba_2003",
                user_id="u_1003",
                bank_name="American Bank",
                iban="SA1520000009876543219821",
                masked_account_number="**** **** **** 9821",
                currency="USD",
                is_default=True,
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(bank_accounts)
        print(f"✓ Created {len(bank_accounts)} bank accounts")
        
        # -------------------------
        # Create Wallets
        # -------------------------
        wallets = [
            Wallet(
                id="w_5001",
                user_id="u_1001",
                currency_code="SAR",
                balance="950.25",
                status=WalletStatus.ACTIVE,
                created_at=datetime(2026, 2, 8, 22, 0, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 12, 9, 40, 0, tzinfo=timezone.utc),
            ),
            Wallet(
                id="w_5002",
                user_id="u_1002",
                currency_code="SAR",
                balance="120.00",
                status=WalletStatus.ACTIVE,
                created_at=datetime(2026, 2, 9, 8, 15, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 11, 17, 30, 0, tzinfo=timezone.utc),
            ),
            Wallet(
                id="w_5003",
                user_id="u_1003",
                currency_code="USD",
                balance="42.75",
                status=WalletStatus.FROZEN,
                created_at=datetime(2026, 2, 10, 13, 20, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 12, 19, 5, 0, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(wallets)
        print(f"✓ Created {len(wallets)} wallets")
        
        # -------------------------
        # Create Transactions
        # -------------------------
        transactions = [
            Transaction(
                id="tx_7001",
                user_id="u_1001",
                wallet_id="w_5001",
                type=TransactionType.TOPUP,
                status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "300.00"},
                counterparty={"kind": "CARD", "ref": "card_****_1221"},
                description="Top up via card",
                created_at=datetime(2026, 2, 12, 9, 30, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 12, 9, 30, 25, tzinfo=timezone.utc),
            ),
            Transaction(
                id="tx_7002",
                user_id="u_1001",
                wallet_id="w_5001",
                type=TransactionType.TRANSFER_USER,
                status=TransactionStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "50.00"},
                counterparty={"kind": "USER", "ref": "u_1002"},
                description="Transfer to another user",
                created_at=datetime(2026, 2, 11, 17, 20, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 11, 17, 20, 10, tzinfo=timezone.utc),
            ),
            Transaction(
                id="tx_7003",
                user_id="u_1003",
                wallet_id="w_5003",
                type=TransactionType.WITHDRAW,
                status=TransactionStatus.FAILED,
                amount={"currency_code": "USD", "value": "25.00"},
                counterparty={"kind": "BANK", "ref": "ba_2003"},
                description="Withdraw to bank account",
                created_at=datetime(2026, 2, 12, 18, 50, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 12, 18, 51, 0, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(transactions)
        print(f"✓ Created {len(transactions)} transactions")
        
        # -------------------------
        # Create Payments
        # -------------------------
        payments = [
            Payment(
                id="pay_3001",
                user_id="u_1001",
                status=PaymentStatus.COMPLETED,
                amount={"currency_code": "SAR", "value": "120.00"},
                merchant={"name": "RASD Store", "merchant_id": "m_9001"},
                description="Order #A1001",
                created_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 8, 21, 56, 51, tzinfo=timezone.utc),
            ),
            Payment(
                id="pay_3002",
                user_id="u_1001",
                status=PaymentStatus.AUTHORIZED,
                amount={"currency_code": "SAR", "value": "55.50"},
                merchant={"name": "Coffee Spot", "merchant_id": "m_9002"},
                description="Coffee beans",
                created_at=datetime(2026, 2, 9, 10, 12, 5, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 9, 10, 12, 5, tzinfo=timezone.utc),
            ),
            Payment(
                id="pay_3003",
                user_id="u_1002",
                status=PaymentStatus.FAILED,
                amount={"currency_code": "SAR", "value": "999.00"},
                merchant={"name": "ElectroMart", "merchant_id": "m_9010"},
                description="Attempted purchase",
                created_at=datetime(2026, 2, 10, 8, 1, 0, tzinfo=timezone.utc),
                updated_at=datetime(2026, 2, 10, 8, 1, 0, tzinfo=timezone.utc),
            ),
        ]
        db.add_all(payments)
        print(f"✓ Created {len(payments)} payments")
        
        # -------------------------
        # Create Admin
        # -------------------------
        admin = Admin(
            id="a_0001",
            username="admin",
            password="admin123",  # In production: hash this
            role="SUPER_ADMIN",
            created_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc),
            updated_at=datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        db.add(admin)
        print("✓ Created admin account")
        
        # Commit all changes
        db.commit()
        print("\n✅ Database seeded successfully!")
        print("\nTest credentials:")
        print("  User: taif.alsaadi@gmail.com / password123")
        print("  Admin: admin / admin123")
        
    except Exception as e:
        print(f"\nError seeding database: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()