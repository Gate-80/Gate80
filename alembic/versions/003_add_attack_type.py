"""
GATE80 — Alembic Migration
003 — Add attack_type column to proxy_requests table.

attack_type stores the behavior classification assigned by the rule-based
classifier at flag time and updated on each subsequent decoy-bound request
using the sliding window (BEHAVIOR_WINDOW_SIZE = 6).

Values: brute_force | scanning | fraud | unknown_suspicious | NULL
NULL means the session was never flagged (normal traffic).

Run with:
    alembic upgrade head
"""

from alembic import op
import sqlalchemy as sa

revision      = "003"
down_revision = "002"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        "proxy_requests",
        sa.Column(
            "attack_type",
            sa.String(50),
            nullable=True,
            comment="brute_force | scanning | fraud | unknown_suspicious | NULL",
        ),
    )


def downgrade() -> None:
    op.drop_column("proxy_requests", "attack_type")