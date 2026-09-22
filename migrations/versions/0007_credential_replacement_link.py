"""Record the credential superseded by each technician recovery."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("device_credentials", sa.Column(
        "replaces_credential_id", postgresql.UUID(as_uuid=True), nullable=True,
    ))
    op.create_foreign_key(
        "device_credentials_replaces_credential_id_fkey",
        "device_credentials", "device_credentials",
        ["replaces_credential_id"], ["id"],
    )
    connection = op.get_bind()
    connection.execute(sa.text(
        "UPDATE device_credentials AS replacement "
        "SET replaces_credential_id = ("
        "SELECT predecessor.id FROM device_credentials AS predecessor "
        "WHERE predecessor.device_id = replacement.device_id "
        "AND (predecessor.created_at, predecessor.id) "
        "< (replacement.created_at, replacement.id) "
        "ORDER BY predecessor.created_at DESC, predecessor.id DESC LIMIT 1"
        ") WHERE replacement.replacement"
    ))
    orphaned = connection.execute(sa.text(
        "SELECT count(*) FROM device_credentials "
        "WHERE replacement AND replaces_credential_id IS NULL"
    )).scalar_one()
    if orphaned:
        raise RuntimeError("replacement_credential_without_predecessor")
    op.drop_column("device_credentials", "replacement")


def downgrade():
    op.add_column("device_credentials", sa.Column(
        "replacement", sa.Boolean(), nullable=False, server_default="false",
    ))
    connection = op.get_bind()
    connection.execute(sa.text(
        "UPDATE device_credentials SET replacement = true "
        "WHERE replaces_credential_id IS NOT NULL"
    ))
    op.drop_constraint(
        "device_credentials_replaces_credential_id_fkey",
        "device_credentials", type_="foreignkey",
    )
    op.drop_column("device_credentials", "replaces_credential_id")
