"""Add endpoint ledger reconciliation state."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


LEDGER_RECORD_TYPES = (
    "'session_started','execution_accepted','execution_started','output_chunk',"
    "'execution_finished','cancellation_requested','worker_stopped','session_closed','output_dropped'"
)


def upgrade():
    op.add_column("sessions", sa.Column("dispatch_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed','cleanup_unknown','lost')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing','cleanup_unknown')"))

    op.add_column("executions", sa.Column("dispatch_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("executions", sa.Column("output_complete", sa.Boolean(), nullable=False, server_default=sa.text("true")))
    op.add_column("executions", sa.Column("output_loss_reason", sa.String(80), nullable=True))
    op.add_column("executions", sa.Column("endpoint_accepted_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("executions", sa.Column("endpoint_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("executions", sa.Column("endpoint_finished_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("execution_output_events", sa.Column("endpoint_observed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table("endpoint_ledger_cursors",
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), primary_key=True),
        sa.Column("ledger_id", sa.String(64), nullable=False),
        sa.Column("acknowledged_through", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("acknowledged_through >= 0", name="endpoint_ledger_ack_nonnegative"))
    op.create_table("endpoint_ledger_records",
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("ledger_id", sa.String(64), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("record_type", sa.String(40), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("record", postgresql.JSONB(), nullable=False),
        sa.Column("endpoint_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("control_plane_received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("sequence > 0", name="endpoint_ledger_sequence_positive"),
        sa.CheckConstraint(f"record_type IN ({LEDGER_RECORD_TYPES})", name="endpoint_ledger_record_type_valid"),
        sa.UniqueConstraint("device_id", "ledger_id", "sequence", name="endpoint_ledger_record_sequence_key"))
    op.create_index("endpoint_ledger_records_device_ledger_sequence",
                    "endpoint_ledger_records", ["device_id", "ledger_id", "sequence"])


def downgrade():
    op.drop_index("endpoint_ledger_records_device_ledger_sequence", table_name="endpoint_ledger_records")
    op.drop_table("endpoint_ledger_records")
    op.drop_table("endpoint_ledger_cursors")

    op.drop_column("execution_output_events", "endpoint_observed_at")
    op.drop_column("executions", "endpoint_finished_at")
    op.drop_column("executions", "endpoint_started_at")
    op.drop_column("executions", "endpoint_accepted_at")
    op.drop_column("executions", "dispatch_requested_at")
    op.drop_column("executions", "output_loss_reason")
    op.drop_column("executions", "output_complete")

    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.execute("UPDATE sessions SET state = 'failed' WHERE state = 'lost'")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed','cleanup_unknown')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing','cleanup_unknown')"))
    op.drop_column("sessions", "dispatch_requested_at")
