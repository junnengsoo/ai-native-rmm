"""Add durable device authorization and revocation attribution."""
from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("devices", sa.Column(
        "authorization_status", sa.String(16), nullable=False, server_default="active"))
    op.add_column("devices", sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("revoked_by", sa.UUID()))
    op.create_foreign_key("devices_revoked_by_fkey", "devices", "callers", ["revoked_by"], ["id"])
    op.create_check_constraint("devices_authorization_status_valid", "devices",
                               "authorization_status IN ('active','revoked')")
    op.create_check_constraint("devices_revocation_fields_consistent", "devices",
                               "(authorization_status = 'active' AND revoked_at IS NULL AND revoked_by IS NULL) OR "
                               "(authorization_status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)")


def downgrade():
    op.drop_constraint("devices_revocation_fields_consistent", "devices", type_="check")
    op.drop_constraint("devices_authorization_status_valid", "devices", type_="check")
    op.drop_constraint("devices_revoked_by_fkey", "devices", type_="foreignkey")
    op.drop_column("devices", "revoked_by")
    op.drop_column("devices", "revoked_at")
    op.drop_column("devices", "authorization_status")
