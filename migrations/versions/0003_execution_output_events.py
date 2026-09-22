"""Retain bounded execution output events."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("execution_output_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=False), primary_key=True),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("executions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stream", sa.String(8), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("byte_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("stream IN ('stdout','stderr')", name="execution_output_stream_valid"),
        sa.CheckConstraint("sequence > 0", name="execution_output_sequence_positive"),
        sa.CheckConstraint("byte_count > 0 AND byte_count <= 8192", name="execution_output_byte_count_bounded"),
        sa.UniqueConstraint("execution_id", "stream", "sequence", name="execution_output_sequence_key"))
    op.create_index("execution_output_execution_stream_sequence",
                    "execution_output_events", ["execution_id", "stream", "sequence"])


def downgrade():
    op.drop_index("execution_output_execution_stream_sequence", table_name="execution_output_events")
    op.drop_table("execution_output_events")
