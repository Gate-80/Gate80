"""
GATE80 — Alembic Migration
006 — Add environment to projects.

Project dashboard cards use environment to distinguish production, staging,
and development API projects.

Run with:
    alembic upgrade head
"""

from alembic import op
import sqlalchemy as sa

revision      = "006"
down_revision = "005"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("environment", sa.String(), nullable=True, server_default="Development"),
    )


def downgrade() -> None:
    op.drop_column("projects", "environment")
