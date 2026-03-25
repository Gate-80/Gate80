
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./proxy_logs.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db():
    """
    Create all tables in proxy_logs.db.
    Includes both ProxyRequest and DecoyRequest so the single DB
    holds the full attack timeline correlatable by session_id.
    """
    from proxy.db.models import ProxyRequest
    from decoy_api.db.log_models import DecoyRequest
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()