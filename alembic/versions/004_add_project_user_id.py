"""
GATE80 — Alembic Migration
004 — Add user ownership to onboarded projects.

Each uploaded OpenAPI project can now be linked to the signed-in user that
created it. Endpoint inventory, proxy config, and decoy config records remain
connected through project_id.

Run with:
    alembic upgrade head
"""

from alembic import op
import sqlalchemy as sa

revision      = "004"
down_revision = "003"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column("user_id", sa.String(), nullable=True),
    )
    op.create_index("ix_projects_user_id", "projects", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_projects_user_id", table_name="projects")
    op.drop_column("projects", "user_id")
