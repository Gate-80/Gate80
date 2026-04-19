# Database connection & sessionpip install sqlalchemy

import os
import stat
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator

# SQLite database URL
# Creates digital_wallet.db file in the project root
SQLALCHEMY_DATABASE_URL = "sqlite:///./digital_wallet.db"
DB_PATH = "./digital_wallet.db"

# Create engine
# connect_args={"check_same_thread": False} is needed only for SQLite
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Dependency to get database session
def get_db() -> Generator[Session, None, None]:
    """
    Database session dependency for FastAPI endpoints.
    Usage:
        @router.get("/users")
        def get_users(db: Session = Depends(get_db)):
            users = db.query(User).all()
            return users
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Initialize database - create all tables.
    Call this once when starting the application.
    """
    Base.metadata.create_all(bind=engine)
    migrate_sqlite_schema()
    
    # Fix file permissions so any user can read/write to prevent readonly errors across different 
    # environments (e.g. if DB was created with sudo or by a different user).
    if os.path.exists(DB_PATH):
        os.chmod(DB_PATH, 
            stat.S_IRUSR | stat.S_IWUSR |  # owner read/write
            stat.S_IRGRP | stat.S_IWGRP |  # group read/write
            stat.S_IROTH | stat.S_IWOTH    # others read/write
        )


def migrate_sqlite_schema():
    """
    Small local SQLite migration helper for columns added during development.
    create_all() creates missing tables, but it does not add columns to
    existing tables.
    """
    if not SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as connection:
        project_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(projects)"))
        }
        if "user_id" not in project_columns:
            connection.execute(text("ALTER TABLE projects ADD COLUMN user_id VARCHAR"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_projects_user_id ON projects (user_id)"))
        if "environment" not in project_columns:
            connection.execute(text("ALTER TABLE projects ADD COLUMN environment VARCHAR DEFAULT 'Development'"))
        if "onboarding_status" not in project_columns:
            connection.execute(text("ALTER TABLE projects ADD COLUMN onboarding_status VARCHAR DEFAULT 'imported'"))
        if "decoy_generation_status" not in project_columns:
            connection.execute(text("ALTER TABLE projects ADD COLUMN decoy_generation_status VARCHAR DEFAULT 'not_started'"))
        if "updated_at" not in project_columns:
            connection.execute(text("ALTER TABLE projects ADD COLUMN updated_at DATETIME"))

        decoy_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(decoy_config)"))
        }
        if "created_by_user_id" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN created_by_user_id VARCHAR"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_decoy_config_created_by_user_id ON decoy_config (created_by_user_id)"))
        if "name" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN name VARCHAR"))
        if "description" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN description VARCHAR"))
        if "headers_template" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN headers_template JSON"))
        if "trigger_condition" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN trigger_condition JSON"))
        if "generation_source" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN generation_source VARCHAR DEFAULT 'auto'"))
        if "review_status" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN review_status VARCHAR DEFAULT 'draft'"))
        if "updated_at" not in decoy_columns:
            connection.execute(text("ALTER TABLE decoy_config ADD COLUMN updated_at DATETIME"))
