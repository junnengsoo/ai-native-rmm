"""Separate logical devices from replaceable endpoint credentials."""
import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("device_name", sa.String(100)))
    connection = op.get_bind()
    connection.execute(sa.text(
        "UPDATE devices SET device_name = 'Device-' || id::text"
    ))
    op.alter_column("devices", "device_name", nullable=False)
    op.create_index(
        "devices_workspace_name_key", "devices",
        ["workspace_id", sa.text("lower(device_name)")], unique=True,
    )
    op.create_table(
        "device_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False, unique=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("activate_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("callers.id")),
        sa.Column("approval_code_hash", sa.Text(), unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("invalidated_at", sa.DateTime(timezone=True)),
        sa.Column("replacement", sa.Boolean(), nullable=False, server_default="false"),
        sa.CheckConstraint(
            "state IN ('pending','active','replaced','expired')",
            name="device_credentials_state_valid",
        ),
    )
    for row in connection.execute(sa.text(
        "SELECT id, public_key, approved_at, last_seen, activate_before FROM devices"
    )).mappings():
        active = row["last_seen"] is not None
        connection.execute(sa.text(
            "INSERT INTO device_credentials "
            "(id, device_id, public_key, state, activate_before, created_at, activated_at, replacement) "
            "VALUES (:id, :device, :key, :state, :deadline, :created, :activated, false)"
        ), {
            "id": uuid.uuid4(), "device": row["id"], "key": row["public_key"],
            "state": "active" if active else "pending",
            "deadline": row["activate_before"] or row["approved_at"], "created": row["approved_at"],
            "activated": row["last_seen"] if active else None,
        })
    op.create_index(
        "device_credentials_one_active", "device_credentials", ["device_id"],
        unique=True, postgresql_where=sa.text("state = 'active'"),
    )
    op.create_index(
        "device_credentials_one_pending", "device_credentials", ["device_id"],
        unique=True, postgresql_where=sa.text("state = 'pending'"),
    )
    op.drop_column("devices", "public_key")
    op.drop_column("devices", "activate_before")


def downgrade():
    op.add_column("devices", sa.Column("public_key", sa.Text()))
    op.add_column("devices", sa.Column("activate_before", sa.DateTime(timezone=True)))
    connection = op.get_bind()
    connection.execute(sa.text(
        "UPDATE devices d SET public_key = c.public_key, activate_before = c.activate_before "
        "FROM (SELECT DISTINCT ON (device_id) device_id, public_key, activate_before "
        "FROM device_credentials ORDER BY device_id, "
        "CASE state WHEN 'active' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, created_at DESC) c "
        "WHERE c.device_id = d.id"
    ))
    op.alter_column("devices", "public_key", nullable=False)
    op.alter_column("devices", "activate_before", nullable=False)
    op.create_unique_constraint("devices_public_key_key", "devices", ["public_key"])
    op.drop_index("device_credentials_one_pending", table_name="device_credentials")
    op.drop_index("device_credentials_one_active", table_name="device_credentials")
    op.drop_table("device_credentials")
    op.drop_index("devices_workspace_name_key", table_name="devices")
    op.drop_column("devices", "device_name")
