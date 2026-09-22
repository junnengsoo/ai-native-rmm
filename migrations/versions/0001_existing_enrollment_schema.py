"""Baseline the enrollment and reachability schema from issue 4."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("admin_hash", sa.Text(), nullable=False, unique=True))
    op.create_table("devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False, unique=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True)),
        sa.Column("activate_before", sa.DateTime(timezone=True)))
    op.create_table("pairings", sa.Column("public_key", sa.Text(), primary_key=True),
        sa.Column("code_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("rate_limits", sa.Column("scope", sa.Text(), primary_key=True),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False))

def downgrade():
    op.drop_table("rate_limits")
    op.drop_table("pairings")
    op.drop_table("devices")
    op.drop_table("workspaces")
