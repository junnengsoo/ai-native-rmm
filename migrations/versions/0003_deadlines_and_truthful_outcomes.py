"""Add cancellation and truthful non-start outcomes."""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed','cleanup_unknown')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing','cleanup_unknown')"))

    op.drop_constraint("executions_status_valid", "executions", type_="check")
    op.create_check_constraint("executions_status_valid", "executions",
                               "status IN ('queued','running','completed','failed_to_start','timed_out','cancelled','outcome_unknown')")


def downgrade():
    op.drop_constraint("executions_status_valid", "executions", type_="check")
    op.create_check_constraint("executions_status_valid", "executions",
                               "status IN ('queued','running','completed','timed_out','outcome_unknown')")

    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_constraint("sessions_state_valid", "sessions", type_="check")
    op.create_check_constraint("sessions_state_valid", "sessions",
                               "state IN ('starting','active','closing','closed','failed')")
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing')"))
