"""Week 6 — add session_id, anomaly_score, routed_to columns

Revision ID: 002
Revises: 001
Create Date: 2026-03-13
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("proxy_requests", sa.Column("session_id",    sa.String(200), nullable=True))
    op.add_column("proxy_requests", sa.Column("anomaly_score", sa.Float(),     nullable=True))
    op.add_column("proxy_requests", sa.Column("routed_to",     sa.String(20),  nullable=False, server_default="backend"))


def downgrade() -> None:
    op.drop_column("proxy_requests", "routed_to")
    op.drop_column("proxy_requests", "anomaly_score")
    op.drop_column("proxy_requests", "session_id")