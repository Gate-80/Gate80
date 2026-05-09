"""Initial platform schema: projects, endpoint_inventory, decoy_config, proxy_config

Revision ID: 001_platform
Revises:
Create Date: 2026-05-08

These four tables previously lived in digital_wallet.db. They are now isolated
in data/gate80_platform.db so the customer's wallet DB only contains wallet data.
"""
from alembic import op
import sqlalchemy as sa


revision = "001_platform"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("customer_name", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), server_default="Development"),
        sa.Column("source_type", sa.String(), nullable=False),
        sa.Column("source_value", sa.String(), nullable=False),
        sa.Column("onboarding_status", sa.String(), server_default="imported"),
        sa.Column("decoy_generation_status", sa.String(), server_default="not_started"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_projects_id", "projects", ["id"])
    op.create_index("ix_projects_user_id", "projects", ["user_id"])

    op.create_table(
        "endpoint_inventory",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("method", sa.String(), nullable=False),
        sa.Column("summary", sa.String()),
        sa.Column("tag", sa.String()),
        sa.Column("requires_auth", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("request_schema_json", sa.JSON()),
        sa.Column("response_schema_json", sa.JSON()),
        sa.Column("risk_score", sa.String(), server_default="0"),
        sa.Column("risk_level", sa.String(), server_default="low"),
        sa.Column("is_selected_for_decoy", sa.Boolean(), server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_endpoint_inventory_id", "endpoint_inventory", ["id"])

    op.create_table(
        "decoy_config",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("endpoint_id", sa.String(), sa.ForeignKey("endpoint_inventory.id"), nullable=False),
        sa.Column("created_by_user_id", sa.String(), nullable=True),
        sa.Column("name", sa.String()),
        sa.Column("description", sa.String()),
        sa.Column("decoy_type", sa.String(), nullable=False),
        sa.Column("status_code", sa.String(), server_default="200"),
        sa.Column("response_template", sa.JSON()),
        sa.Column("headers_template", sa.JSON()),
        sa.Column("trigger_condition", sa.JSON()),
        sa.Column("delay_ms", sa.String(), server_default="0"),
        sa.Column("generation_source", sa.String(), server_default="auto"),
        sa.Column("review_status", sa.String(), server_default="draft"),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_decoy_config_id", "decoy_config", ["id"])
    op.create_index("ix_decoy_config_created_by_user_id", "decoy_config", ["created_by_user_id"])

    op.create_table(
        "proxy_config",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("backend_base_url", sa.String(), nullable=False),
        sa.Column("proxy_host", sa.String(), server_default="127.0.0.1"),
        sa.Column("listen_port", sa.String(), server_default="8080"),
        sa.Column("api_key", sa.String()),
        sa.Column("mode", sa.String(), server_default="reverse_proxy"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_proxy_config_id", "proxy_config", ["id"])
    op.create_index("ix_proxy_config_project_id", "proxy_config", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_proxy_config_project_id", table_name="proxy_config")
    op.drop_index("ix_proxy_config_id", table_name="proxy_config")
    op.drop_table("proxy_config")

    op.drop_index("ix_decoy_config_created_by_user_id", table_name="decoy_config")
    op.drop_index("ix_decoy_config_id", table_name="decoy_config")
    op.drop_table("decoy_config")

    op.drop_index("ix_endpoint_inventory_id", table_name="endpoint_inventory")
    op.drop_table("endpoint_inventory")

    op.drop_index("ix_projects_user_id", table_name="projects")
    op.drop_index("ix_projects_id", table_name="projects")
    op.drop_table("projects")
