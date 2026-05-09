"""
Alembic environment for the GATE80 platform DB (data/gate80_platform.db).

Mirrors the existing proxy alembic/env.py but points at the platform models.
"""
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Register platform models on Base so --autogenerate detects them.
from gate80_platform.db.database import Base
import gate80_platform.db.models  # noqa: F401

config = context.config
fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Generate SQL without a live DB connection."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against the live DB. Used by `alembic upgrade head`."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
