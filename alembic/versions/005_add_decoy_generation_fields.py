"""
GATE80 — Alembic Migration
005 — Add decoy generation workflow fields.

Adds project-level decoy generation status and richer decoy config metadata
for generated draft/deployed decoys.

Run with:
    alembic upgrade head
"""

from alembic import op
import sqlalchemy as sa

revision      = "005"
down_revision = "004"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column("projects", sa.Column("onboarding_status", sa.String(), nullable=True, server_default="imported"))
    op.add_column("projects", sa.Column("decoy_generation_status", sa.String(), nullable=True, server_default="not_started"))
    op.add_column("projects", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))

    op.add_column("decoy_config", sa.Column("created_by_user_id", sa.String(), nullable=True))
    op.create_index("ix_decoy_config_created_by_user_id", "decoy_config", ["created_by_user_id"])
    op.add_column("decoy_config", sa.Column("name", sa.String(), nullable=True))
    op.add_column("decoy_config", sa.Column("description", sa.String(), nullable=True))
    op.add_column("decoy_config", sa.Column("headers_template", sa.JSON(), nullable=True))
    op.add_column("decoy_config", sa.Column("trigger_condition", sa.JSON(), nullable=True))
    op.add_column("decoy_config", sa.Column("generation_source", sa.String(), nullable=True, server_default="auto"))
    op.add_column("decoy_config", sa.Column("review_status", sa.String(), nullable=True, server_default="draft"))
    op.add_column("decoy_config", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("decoy_config", "updated_at")
    op.drop_column("decoy_config", "review_status")
    op.drop_column("decoy_config", "generation_source")
    op.drop_column("decoy_config", "trigger_condition")
    op.drop_column("decoy_config", "headers_template")
    op.drop_column("decoy_config", "description")
    op.drop_column("decoy_config", "name")
    op.drop_index("ix_decoy_config_created_by_user_id", table_name="decoy_config")
    op.drop_column("decoy_config", "created_by_user_id")

    op.drop_column("projects", "updated_at")
    op.drop_column("projects", "decoy_generation_status")
    op.drop_column("projects", "onboarding_status")
