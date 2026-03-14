"""Initial proxy_requests schema

Revision ID: 001
Revises: 
Create Date: 2026-01-01
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "proxy_requests",
        sa.Column("id",                   sa.Integer(),     primary_key=True, autoincrement=True),
        sa.Column("request_id",           sa.String(50),    nullable=False,   unique=True),
        sa.Column("timestamp",            sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("client_ip",            sa.String(50)),
        sa.Column("method",               sa.String(10),    nullable=False),
        sa.Column("path",                 sa.String(500),   nullable=False),
        sa.Column("query_params",         sa.Text()),
        sa.Column("headers",              sa.Text()),
        sa.Column("body",                 sa.Text()),
        sa.Column("response_status",      sa.Integer()),
        sa.Column("response_time_ms",     sa.Integer()),
        sa.Column("forwarded_to_backend", sa.Boolean(),     default=True),
        sa.Column("backend_error",        sa.String(200)),
        sa.Column("flagged_as_suspicious",sa.Boolean(),     default=False),
        sa.Column("suspicion_reason",     sa.String(200)),
        sa.Column("created_at",           sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("proxy_requests")