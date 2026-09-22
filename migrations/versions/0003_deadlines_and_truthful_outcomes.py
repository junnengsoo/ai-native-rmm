"""Add investigation deadlines and explicit expiry outcomes."""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.add_column("sessions", sa.Column("idle_timeout_ms", sa.Integer(), nullable=False, server_default="1800000"))
    op.add_column("sessions", sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))
    op.add_column("sessions", sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False,
                                        server_default=sa.text("now() + interval '8 hours'")))
    op.create_check_constraint("sessions_idle_timeout_valid", "sessions",
                               "idle_timeout_ms > 0 AND idle_timeout_ms <= 7200000")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed','cleanup_unknown')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing','cleanup_unknown')"))

    op.drop_constraint("executions_status_valid", "executions", type_="check")
    op.add_column("executions", sa.Column("start_deadline_at", sa.DateTime(timezone=True), nullable=False,
                                          server_default=sa.text("now() + interval '60 seconds'")))
    op.create_check_constraint("executions_status_valid", "executions",
                               "status IN ('queued','running','completed','expired','timed_out','outcome_unknown')")


def downgrade():
    op.drop_constraint("executions_status_valid", "executions", type_="check")
    op.drop_column("executions", "start_deadline_at")
    op.create_check_constraint("executions_status_valid", "executions",
                               "status IN ('queued','running','completed','timed_out','outcome_unknown')")

    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.drop_constraint("sessions_idle_timeout_valid", "sessions", type_="check")
    op.drop_column("sessions", "absolute_expires_at")
    op.drop_column("sessions", "last_activity_at")
    op.drop_column("sessions", "idle_timeout_ms")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing')"))
