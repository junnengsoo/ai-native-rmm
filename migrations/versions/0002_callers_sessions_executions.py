"""Add caller credentials and durable investigation records."""
import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("callers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False), sa.Column("role", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('admin', 'operator')", name="callers_role_valid"),
        sa.CheckConstraint("status IN ('active', 'revoked')", name="callers_status_valid"),
        sa.UniqueConstraint("workspace_id", "name", name="callers_workspace_name_key"))
    op.create_table("caller_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("caller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("callers.id"), nullable=False),
        sa.Column("credential_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)))
    connection = op.get_bind()
    for row in connection.execute(sa.text("SELECT id, admin_hash FROM workspaces")).mappings():
        caller_id = uuid.uuid4()
        connection.execute(sa.text("INSERT INTO callers (id, workspace_id, name, role) VALUES (:id,:workspace,'bootstrap-admin','admin')"),
                           {"id": caller_id, "workspace": row["id"]})
        connection.execute(sa.text("INSERT INTO caller_credentials (id, caller_id, credential_hash) VALUES (:id,:caller,:hash)"),
                           {"id": uuid.uuid4(), "caller": caller_id, "hash": row["admin_hash"]})
    op.drop_column("workspaces", "admin_hash")
    op.create_table("sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("caller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("callers.id"), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ready_at", sa.DateTime(timezone=True)), sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("state IN ('starting','active','closing','closed','failed')", name="sessions_state_valid"))
    op.create_index("sessions_one_live_per_device", "sessions", ["device_id"], unique=True,
                    postgresql_where=sa.text("state IN ('starting','active','closing')"))
    op.create_table("executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sessions.id"), nullable=False),
        sa.Column("caller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("callers.id"), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False), sa.Column("script", sa.Text(), nullable=False),
        sa.Column("script_sha256", sa.String(64), nullable=False), sa.Column("timeout_ms", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False), sa.Column("invocation_outcome", sa.String(32)),
        sa.Column("outcome_reason", sa.String(64)), sa.Column("last_confirmed_status", sa.String(24)),
        sa.Column("exit_code", sa.Integer()), sa.Column("exit_code_source", sa.String(32)),
        sa.Column("had_errors", sa.Boolean()), sa.Column("stdout", sa.Text()), sa.Column("stderr", sa.Text()),
        sa.Column("duration_ms", sa.Float()), sa.Column("capture_truncated", sa.Boolean()),
        sa.Column("last_native_exit_code", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("timeout_ms > 0", name="executions_timeout_positive"),
        sa.CheckConstraint("status IN ('queued','running','completed','timed_out','outcome_unknown')", name="executions_status_valid"),
        sa.UniqueConstraint("caller_id", "idempotency_key", name="executions_caller_idempotency_key"))
    op.create_index("executions_one_live_per_session", "executions", ["session_id"], unique=True,
                    postgresql_where=sa.text("status IN ('queued','running')"))
    op.create_table("audit_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("workspaces.id"), nullable=False),
        sa.Column("caller_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("callers.id"), nullable=False),
        sa.Column("action", sa.String(80), nullable=False), sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False), sa.Column("script", sa.Text()),
        sa.Column("script_sha256", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()))

def downgrade():
    op.drop_table("audit_records")
    op.drop_index("executions_one_live_per_session", table_name="executions")
    op.drop_table("executions")
    op.drop_index("sessions_one_live_per_device", table_name="sessions")
    op.drop_table("sessions")
    op.add_column("workspaces", sa.Column("admin_hash", sa.Text(), nullable=True))
    connection = op.get_bind()
    connection.execute(sa.text("UPDATE workspaces w SET admin_hash=c.credential_hash FROM callers a JOIN caller_credentials c ON c.caller_id=a.id WHERE a.workspace_id=w.id AND a.role='admin' AND c.revoked_at IS NULL"))
    op.alter_column("workspaces", "admin_hash", nullable=False)
    op.create_unique_constraint("workspaces_admin_hash_key", "workspaces", ["admin_hash"])
    op.drop_table("caller_credentials")
    op.drop_table("callers")
