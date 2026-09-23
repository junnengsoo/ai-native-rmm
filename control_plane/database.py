"""SQLAlchemy Core schema and repositories; no ORM state is used."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Iterator, Literal

from alembic import command
from alembic.config import Config
from sqlalchemy import (BigInteger, Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Identity, Index, Integer,
                        MetaData, String, Table, Text, UniqueConstraint, case,
                        create_engine, delete, func, inspect, insert, or_, select,
                        text, update)
from sqlalchemy.dialects.postgresql import JSONB, UUID, insert as postgresql_insert
from sqlalchemy.engine import Connection, Engine, RowMapping
from sqlalchemy.exc import IntegrityError

from .output_queries import (
    MAX_QUERY_SCAN_EVENTS,
    query_retained_output,
    range_retained_output,
    tail_retained_output,
)

metadata = MetaData()
UNRESOLVED_SESSION_STATES = ("starting", "active", "closing", "cleanup_unknown")
RecoveryOutcome = Literal["pending", "not_found", "revoked", "device_busy",
                          "recovery_pending", "invalid_code"]
workspaces = Table("workspaces", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True), Column("name", Text, nullable=False))
callers = Table("callers", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False),
    Column("name", Text, nullable=False), Column("role", String(16), nullable=False),
    Column("status", String(16), nullable=False, server_default="active"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("role IN ('admin', 'operator')", name="callers_role_valid"),
    CheckConstraint("status IN ('active', 'revoked')", name="callers_status_valid"),
    UniqueConstraint("workspace_id", "name", name="callers_workspace_name_key"))
caller_credentials = Table("caller_credentials", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("caller_id", UUID(as_uuid=True), ForeignKey("callers.id"), nullable=False),
    Column("credential_hash", Text, nullable=False, unique=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("revoked_at", DateTime(timezone=True)))
devices = Table("devices", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False),
    Column("device_name", String(100), nullable=False),
    Column("approved_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_seen", DateTime(timezone=True)),
    Column("authorization_status", String(16), nullable=False, server_default="active"),
    Column("revoked_at", DateTime(timezone=True)),
    Column("revoked_by", UUID(as_uuid=True), ForeignKey("callers.id")),
    CheckConstraint("authorization_status IN ('active', 'revoked')", name="devices_authorization_status_valid"),
    CheckConstraint("(authorization_status = 'active' AND revoked_at IS NULL AND revoked_by IS NULL) OR "
                    "(authorization_status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL)",
                    name="devices_revocation_fields_consistent"))
Index("devices_workspace_name_key", devices.c.workspace_id, func.lower(devices.c.device_name), unique=True)
device_credentials = Table("device_credentials", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("device_id", UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False),
    Column("public_key", Text, nullable=False, unique=True),
    Column("state", String(16), nullable=False),
    Column("activate_before", DateTime(timezone=True), nullable=False),
    Column("approved_by", UUID(as_uuid=True), ForeignKey("callers.id")),
    Column("approval_code_hash", Text, unique=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("activated_at", DateTime(timezone=True)),
    Column("invalidated_at", DateTime(timezone=True)),
    Column("replaces_credential_id", UUID(as_uuid=True), ForeignKey("device_credentials.id")),
    CheckConstraint("state IN ('pending', 'active', 'replaced', 'expired')",
                    name="device_credentials_state_valid"))
Index("device_credentials_one_active", device_credentials.c.device_id, unique=True,
      postgresql_where=device_credentials.c.state == "active")
Index("device_credentials_one_pending", device_credentials.c.device_id, unique=True,
      postgresql_where=device_credentials.c.state == "pending")
pairings = Table("pairings", metadata, Column("public_key", Text, primary_key=True),
    Column("code_hash", Text, nullable=False, unique=True),
    Column("expires_at", DateTime(timezone=True), nullable=False))
rate_limits = Table("rate_limits", metadata, Column("scope", Text, primary_key=True),
    Column("window_started_at", DateTime(timezone=True), nullable=False),
    Column("attempt_count", Integer, nullable=False))
sessions = Table("sessions", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False),
    Column("device_id", UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False),
    Column("caller_id", UUID(as_uuid=True), ForeignKey("callers.id"), nullable=False),
    Column("state", String(16), nullable=False),
    Column("dispatch_requested_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("ready_at", DateTime(timezone=True)), Column("closed_at", DateTime(timezone=True)),
    CheckConstraint("state IN ('starting', 'active', 'closing', 'closed', 'failed', 'cleanup_unknown', 'lost')", name="sessions_state_valid"))
Index("sessions_one_live_per_device", sessions.c.device_id, unique=True,
      postgresql_where=sessions.c.state.in_(("starting", "active", "closing", "cleanup_unknown")))
executions = Table("executions", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False),
    Column("session_id", UUID(as_uuid=True), ForeignKey("sessions.id"), nullable=False),
    Column("caller_id", UUID(as_uuid=True), ForeignKey("callers.id"), nullable=False),
    Column("idempotency_key", String(200), nullable=False), Column("script", Text, nullable=False),
    Column("script_sha256", String(64), nullable=False), Column("timeout_ms", Integer, nullable=False),
    Column("status", String(24), nullable=False), Column("invocation_outcome", String(32)),
    Column("outcome_reason", String(64)), Column("last_confirmed_status", String(24)),
    Column("exit_code", Integer), Column("exit_code_source", String(32)),
    Column("had_errors", Boolean), Column("stdout", Text), Column("stderr", Text),
    Column("duration_ms", Float), Column("capture_truncated", Boolean),
    Column("output_complete", Boolean, nullable=False, server_default="true"),
    Column("output_loss_reason", String(80)),
    Column("last_native_exit_code", Integer),
    Column("dispatch_requested_at", DateTime(timezone=True)),
    Column("endpoint_accepted_at", DateTime(timezone=True)),
    Column("endpoint_started_at", DateTime(timezone=True)),
    Column("endpoint_finished_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("started_at", DateTime(timezone=True)), Column("finished_at", DateTime(timezone=True)),
    CheckConstraint("timeout_ms > 0", name="executions_timeout_positive"),
    CheckConstraint("status IN ('queued', 'running', 'completed', 'failed_to_start', 'timed_out', 'cancelled', 'outcome_unknown')", name="executions_status_valid"),
    UniqueConstraint("caller_id", "idempotency_key", name="executions_caller_idempotency_key"))
Index("executions_one_live_per_session", executions.c.session_id, unique=True,
      postgresql_where=executions.c.status.in_(("queued", "running")))
execution_output_events = Table("execution_output_events", metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    Column("execution_id", UUID(as_uuid=True), ForeignKey("executions.id", ondelete="CASCADE"), nullable=False),
    Column("stream", String(8), nullable=False),
    Column("sequence", Integer, nullable=False), Column("text", Text, nullable=False),
    Column("byte_count", Integer, nullable=False),
    Column("endpoint_observed_at", DateTime(timezone=True)),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("stream IN ('stdout', 'stderr')", name="execution_output_stream_valid"),
    CheckConstraint("sequence > 0", name="execution_output_sequence_positive"),
    CheckConstraint("byte_count > 0 AND byte_count <= 8192", name="execution_output_byte_count_bounded"),
    UniqueConstraint("execution_id", "stream", "sequence", name="execution_output_sequence_key"))
Index("execution_output_execution_stream_sequence", execution_output_events.c.execution_id,
      execution_output_events.c.stream, execution_output_events.c.sequence)
endpoint_ledger_cursors = Table("endpoint_ledger_cursors", metadata,
    Column("device_id", UUID(as_uuid=True), ForeignKey("devices.id"), primary_key=True),
    Column("ledger_id", String(64), nullable=False),
    Column("acknowledged_through", BigInteger, nullable=False, server_default="0"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("acknowledged_through >= 0", name="endpoint_ledger_ack_nonnegative"))
endpoint_ledger_records = Table("endpoint_ledger_records", metadata,
    Column("device_id", UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False),
    Column("ledger_id", String(64), nullable=False),
    Column("sequence", BigInteger, nullable=False),
    Column("record_type", String(40), nullable=False),
    Column("record_hash", String(64), nullable=False),
    Column("record", JSONB, nullable=False),
    Column("endpoint_observed_at", DateTime(timezone=True), nullable=False),
    Column("control_plane_received_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    CheckConstraint("sequence > 0", name="endpoint_ledger_sequence_positive"),
    CheckConstraint(
        "record_type IN ('session_started','execution_accepted','execution_started','output_chunk',"
        "'execution_finished','cancellation_requested','worker_stopped','session_closed','output_dropped')",
        name="endpoint_ledger_record_type_valid"),
    UniqueConstraint("device_id", "ledger_id", "sequence", name="endpoint_ledger_record_sequence_key"))
Index("endpoint_ledger_records_device_ledger_sequence", endpoint_ledger_records.c.device_id,
      endpoint_ledger_records.c.ledger_id, endpoint_ledger_records.c.sequence)
audit_records = Table("audit_records", metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("workspace_id", UUID(as_uuid=True), ForeignKey("workspaces.id"), nullable=False),
    Column("caller_id", UUID(as_uuid=True), ForeignKey("callers.id"), nullable=False),
    Column("action", String(80), nullable=False), Column("resource_type", String(40), nullable=False),
    Column("resource_id", UUID(as_uuid=True), nullable=False), Column("script", Text),
    Column("script_sha256", String(64)),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()))

def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

@lru_cache(maxsize=1)
def engine() -> Engine:
    database_url = os.environ["RMM_DATABASE_URL"]
    if database_url.startswith("postgresql://"):
        database_url = "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    return create_engine(database_url, pool_pre_ping=True,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=5000 -c lock_timeout=2000"})

@contextmanager
def transaction() -> Iterator[Connection]:
    with engine().begin() as connection:
        yield connection

def _alembic_config() -> Config:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config = Config(os.path.join(root, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(root, "migrations"))
    config.attributes["connection"] = engine()
    return config

def initialize() -> None:
    """Migrate either an empty database or the pre-Alembic #4 schema."""
    existing = set(inspect(engine()).get_table_names())
    legacy = {"workspaces", "devices", "pairings", "rate_limits"}
    if "alembic_version" not in existing and existing & legacy:
        if not legacy.issubset(existing):
            raise RuntimeError("partial_legacy_schema")
        command.stamp(_alembic_config(), "0001")
    command.upgrade(_alembic_config(), "head")

def acquire_enrollment_lock(connection: Connection) -> None:
    connection.execute(select(func.pg_advisory_xact_lock(4004)))

def increment_rate_limit(scope: str) -> int:
    now = datetime.now(timezone.utc)
    expired = rate_limits.c.window_started_at <= now - timedelta(minutes=1)
    statement = postgresql_insert(rate_limits).values(scope=scope, window_started_at=now, attempt_count=1)
    statement = statement.on_conflict_do_update(index_elements=[rate_limits.c.scope], set_={
        "window_started_at": case((expired, now), else_=rate_limits.c.window_started_at),
        "attempt_count": case((expired, 1), else_=func.least(rate_limits.c.attempt_count + 1, 100000)),
    }).returning(rate_limits.c.attempt_count)
    with transaction() as connection:
        return connection.execute(statement).scalar_one()

def authenticate_credential(credential_hash: str) -> RowMapping | None:
    statement = select(callers.c.id, callers.c.workspace_id, callers.c.role).join(
        caller_credentials, caller_credentials.c.caller_id == callers.c.id).where(
        caller_credentials.c.credential_hash == credential_hash,
        caller_credentials.c.revoked_at.is_(None), callers.c.status == "active")
    with transaction() as connection:
        return connection.execute(statement).mappings().one_or_none()

def list_workspace_devices(workspace_id: uuid.UUID, after: uuid.UUID | None, limit: int) -> list[RowMapping]:
    activation_deadline = select(func.max(device_credentials.c.activate_before)).where(
        device_credentials.c.device_id == devices.c.id,
        device_credentials.c.state == "pending").scalar_subquery()
    statement = select(devices.c.id, devices.c.device_name, devices.c.approved_at, devices.c.last_seen,
                       activation_deadline.label("activate_before"), devices.c.authorization_status,
                       devices.c.revoked_at, devices.c.revoked_by).where(
                           devices.c.workspace_id == workspace_id)
    if after is not None:
        statement = statement.where(devices.c.id > after)
    with transaction() as connection:
        return list(connection.execute(statement.order_by(devices.c.id).limit(limit)).mappings())

def approve_pairing(code_hash: str, workspace_id: uuid.UUID, actor_id: uuid.UUID,
                    device_name: str) -> uuid.UUID | None:
    with transaction() as connection:
        acquire_enrollment_lock(connection)
        pending = connection.execute(delete(pairings).where(
            pairings.c.code_hash == code_hash, pairings.c.expires_at > func.now()
        ).returning(pairings.c.public_key, pairings.c.expires_at)).mappings().one_or_none()
        if pending is None:
            return None
        device_id = uuid.uuid4()
        connection.execute(insert(devices).values(id=device_id, workspace_id=workspace_id,
            device_name=device_name))
        connection.execute(insert(device_credentials).values(
            id=uuid.uuid4(), device_id=device_id, public_key=pending["public_key"],
            state="pending", activate_before=pending["expires_at"], approved_by=actor_id,
            approval_code_hash=code_hash))
        return device_id

def recover_device(code_hash: str, workspace_id: uuid.UUID, actor_id: uuid.UUID,
                   device_id: uuid.UUID) -> tuple[RecoveryOutcome, RowMapping | None]:
    """Bind one freshly proven pending key to an existing device without activating it."""
    with transaction() as connection:
        acquire_enrollment_lock(connection)
        device = connection.execute(select(devices).where(
            devices.c.id == device_id, devices.c.workspace_id == workspace_id
        ).with_for_update()).mappings().one_or_none()
        if device is None:
            return "not_found", None
        if device["authorization_status"] == "revoked":
            return "revoked", device
        connection.execute(update(device_credentials).where(
            device_credentials.c.device_id == device_id,
            device_credentials.c.state == "pending",
            device_credentials.c.activate_before <= func.now()
        ).values(state="expired", invalidated_at=func.now()))
        retry = connection.execute(select(device_credentials).where(
            device_credentials.c.device_id == device_id,
            device_credentials.c.approval_code_hash == code_hash,
            device_credentials.c.approved_by == actor_id,
            device_credentials.c.state == "pending")).mappings().one_or_none()
        if retry is not None:
            return "pending", device
        unresolved = connection.execute(select(sessions.c.id).where(
            sessions.c.device_id == device_id,
            sessions.c.state.in_(UNRESOLVED_SESSION_STATES))
        ).first()
        if unresolved is not None:
            return "device_busy", device
        if connection.execute(select(device_credentials.c.id).where(
            device_credentials.c.device_id == device_id,
            device_credentials.c.state == "pending")).first():
            return "recovery_pending", device
        pending = connection.execute(delete(pairings).where(
            pairings.c.code_hash == code_hash, pairings.c.expires_at > func.now()
        ).returning(pairings.c.public_key, pairings.c.expires_at)).mappings().one_or_none()
        if pending is None:
            return "invalid_code", device
        predecessor_id = connection.execute(select(device_credentials.c.id).where(
            device_credentials.c.device_id == device_id
        ).order_by(
            (device_credentials.c.state == "active").desc(),
            device_credentials.c.created_at.desc(),
            device_credentials.c.id.desc(),
        ).limit(1).with_for_update()).scalar_one()
        connection.execute(insert(device_credentials).values(
            id=uuid.uuid4(), device_id=device_id, public_key=pending["public_key"],
            state="pending", activate_before=pending["expires_at"], approved_by=actor_id,
            approval_code_hash=code_hash, replaces_credential_id=predecessor_id))
        connection.execute(insert(audit_records).values(
            id=uuid.uuid4(), workspace_id=workspace_id, caller_id=actor_id,
            action="device.recovery_approved", resource_type="device", resource_id=device_id))
        return "pending", device

def rename_workspace_device(workspace_id: uuid.UUID, device_id: uuid.UUID,
                            device_name: str) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(update(devices).where(
            devices.c.id == device_id, devices.c.workspace_id == workspace_id
        ).values(device_name=device_name).returning(devices.c.id, devices.c.device_name)
        ).mappings().one_or_none()

def authenticate_device(public_key: str, pairing_code: str) -> dict[str, object]:
    with transaction() as connection:
        acquire_enrollment_lock(connection)
        credential = connection.execute(select(
            device_credentials, devices.c.workspace_id, devices.c.authorization_status
        ).join(devices, devices.c.id == device_credentials.c.device_id).where(
            device_credentials.c.public_key == public_key).with_for_update()
        ).mappings().one_or_none()
        if credential is not None:
            device_id = credential["device_id"]
            device = connection.execute(select(devices).where(
                devices.c.id == device_id).with_for_update()).mappings().one()
            if device["authorization_status"] == "revoked":
                return {"state": "denied"}
            if credential["state"] in ("replaced", "expired"):
                return {"state": "denied"}
            replaced = False
            if credential["state"] == "pending":
                if credential["activate_before"] <= datetime.now(timezone.utc):
                    connection.execute(update(device_credentials).where(
                        device_credentials.c.id == credential["id"]
                    ).values(state="expired", invalidated_at=func.now()))
                    return {"state": "denied"}
                if credential["replaces_credential_id"] is not None:
                    if connection.execute(select(sessions.c.id).where(
                        sessions.c.device_id == device_id,
                        sessions.c.state.in_(UNRESOLVED_SESSION_STATES)
                    )).first():
                        return {"state": "denied"}
                    connection.execute(update(device_credentials).where(
                        device_credentials.c.device_id == device_id,
                        device_credentials.c.state == "active"
                    ).values(state="replaced", invalidated_at=func.now()))
                    connection.execute(insert(audit_records).values(
                        id=uuid.uuid4(), workspace_id=device["workspace_id"],
                        caller_id=credential["approved_by"], action="device.recovered",
                        resource_type="device", resource_id=device_id))
                    replaced = True
                connection.execute(update(device_credentials).where(
                    device_credentials.c.id == credential["id"],
                    device_credentials.c.state == "pending"
                ).values(state="active", activated_at=func.now()))
            connection.execute(update(devices).where(
                devices.c.id == device_id, devices.c.authorization_status == "active"
            ).values(last_seen=func.now()))
            return {"state": "online", "device_id": str(device_id),
                    "credential_id": str(credential["id"]), "replaced": replaced,
                    "heartbeat_seconds": 15, "stale_seconds": 45}
        connection.execute(delete(pairings).where(pairings.c.expires_at <= func.now()))
        if connection.execute(select(pairings.c.public_key).where(pairings.c.public_key == public_key)).first():
            return {"state": "pending"}
        if connection.execute(select(func.count()).select_from(pairings)).scalar_one() >= 1000:
            return {"state": "rate_limited"}
        connection.execute(insert(pairings).values(public_key=public_key, code_hash=digest(pairing_code),
            expires_at=func.now() + text("interval '10 minutes'")))
        return {"state": "pending", "code": pairing_code, "expires_in_seconds": 600}

def record_heartbeat(device_id: uuid.UUID | str, credential_id: uuid.UUID | str) -> bool:
    with transaction() as connection:
        return connection.execute(update(devices).where(
            devices.c.id == device_id, devices.c.authorization_status == "active",
            select(device_credentials.c.id).where(
                device_credentials.c.id == credential_id,
                device_credentials.c.device_id == devices.c.id,
                device_credentials.c.state == "active").exists()
        ).values(last_seen=func.now())).rowcount == 1

def get_workspace_device(workspace_id: uuid.UUID, device_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(select(devices).where(
            devices.c.id == device_id, devices.c.workspace_id == workspace_id
        )).mappings().one_or_none()

def revoke_workspace_device(workspace_id: uuid.UUID, actor_id: uuid.UUID,
                            device_id: uuid.UUID) -> tuple[RowMapping, bool] | None:
    """Persist revocation exactly once before any best-effort remote cleanup."""
    with transaction() as connection:
        device = connection.execute(select(devices).where(
            devices.c.id == device_id, devices.c.workspace_id == workspace_id
        ).with_for_update()).mappings().one_or_none()
        if device is None:
            return None
        changed = device["authorization_status"] == "active"
        if changed:
            device = connection.execute(update(devices).where(
                devices.c.id == device_id, devices.c.authorization_status == "active"
            ).values(authorization_status="revoked", revoked_at=func.now(), revoked_by=actor_id)
             .returning(devices)).mappings().one()
            connection.execute(insert(audit_records).values(
                id=uuid.uuid4(), workspace_id=workspace_id, caller_id=actor_id,
                action="device.revoked", resource_type="device", resource_id=device_id))
        return device, changed

def get_live_device_session(workspace_id: uuid.UUID, device_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(select(sessions).where(
            sessions.c.workspace_id == workspace_id, sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active", "closing"))
        ).order_by(sessions.c.created_at.desc()).limit(1)).mappings().one_or_none()

def mark_device_revocation_cleanup_unknown(device_id: uuid.UUID) -> list[uuid.UUID]:
    """Finalize live work conservatively when endpoint cleanup cannot be proven."""
    with transaction() as connection:
        live_sessions = select(sessions.c.id).where(
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active", "closing")))
        uncertain = or_(
            executions.c.status.in_(("queued", "running")),
            (executions.c.status == "outcome_unknown") & executions.c.outcome_reason.in_((
                "endpoint_disconnected", "dispatch_confirmation_lost")),
        )
        affected = list(connection.execute(select(executions.c.id).where(
            executions.c.session_id.in_(live_sessions), uncertain)).scalars())
        connection.execute(update(executions).where(
            executions.c.session_id.in_(live_sessions),
            uncertain).values(
                status="outcome_unknown", outcome_reason="device_revoked_cleanup_unconfirmed",
                last_confirmed_status=case(
                    (executions.c.status == "outcome_unknown", executions.c.last_confirmed_status),
                    else_=executions.c.status),
                finished_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state == "starting").values(state="failed", closed_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("active", "closing"))).values(
                state="cleanup_unknown", closed_at=func.now()))
        return affected

def create_workspace_with_admin(name: str, credential_hash: str) -> tuple[uuid.UUID, uuid.UUID]:
    workspace_id, caller_id = uuid.uuid4(), uuid.uuid4()
    with transaction() as connection:
        connection.execute(insert(workspaces).values(id=workspace_id, name=name))
        connection.execute(insert(callers).values(id=caller_id, workspace_id=workspace_id,
                                                  name="bootstrap-admin", role="admin"))
        connection.execute(insert(caller_credentials).values(id=uuid.uuid4(), caller_id=caller_id,
                                                              credential_hash=credential_hash))
    return workspace_id, caller_id

def create_caller(workspace_id: uuid.UUID, actor_id: uuid.UUID, name: str, role: str,
                  credential_hash: str) -> tuple[uuid.UUID, uuid.UUID]:
    caller_id, credential_id = uuid.uuid4(), uuid.uuid4()
    with transaction() as connection:
        connection.execute(insert(callers).values(
            id=caller_id, workspace_id=workspace_id, name=name, role=role))
        connection.execute(insert(caller_credentials).values(
            id=credential_id, caller_id=caller_id, credential_hash=credential_hash))
        connection.execute(insert(audit_records).values(
            id=uuid.uuid4(), workspace_id=workspace_id, caller_id=actor_id,
            action="caller.created", resource_type="caller", resource_id=caller_id))
    return caller_id, credential_id

def create_starting_session(workspace_id: uuid.UUID, caller_id: uuid.UUID,
                            device_id: uuid.UUID) -> RowMapping | None:
    session_id = uuid.uuid4()
    try:
        with transaction() as connection:
            owned = connection.execute(select(devices.c.id).where(
                devices.c.id == device_id, devices.c.workspace_id == workspace_id,
                devices.c.authorization_status == "active",
                devices.c.last_seen > func.now() - text("interval '45 seconds'"),
                ~select(device_credentials.c.id).where(
                    device_credentials.c.device_id == devices.c.id,
                    device_credentials.c.state == "pending",
                    device_credentials.c.replaces_credential_id.is_not(None)).exists()
            ).with_for_update()).scalar_one_or_none()
            if owned is None:
                return None
            connection.execute(insert(sessions).values(
                id=session_id, workspace_id=workspace_id, device_id=device_id,
                caller_id=caller_id, state="starting"))
            connection.execute(insert(audit_records).values(
                id=uuid.uuid4(), workspace_id=workspace_id, caller_id=caller_id,
                action="session.requested", resource_type="session", resource_id=session_id))
            return connection.execute(select(sessions).where(sessions.c.id == session_id)).mappings().one()
    except IntegrityError as error:
        if getattr(error.orig, "sqlstate", None) == "23505":
            raise RuntimeError("device_busy") from None
        raise

def mark_session_dispatch_requested(session_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        row = connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state == "starting"
        ).values(dispatch_requested_at=func.coalesce(
            sessions.c.dispatch_requested_at, func.now())).returning(sessions)).mappings().one_or_none()
        return row

def mark_session_cleanup_unknown(session_id: uuid.UUID) -> None:
    with transaction() as connection:
        connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state.in_(("active", "closing"))
        ).values(state="cleanup_unknown", closed_at=func.now()))

def get_workspace_session(workspace_id: uuid.UUID, session_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(select(sessions).where(
            sessions.c.id == session_id, sessions.c.workspace_id == workspace_id)).mappings().one_or_none()

def begin_session_close(workspace_id: uuid.UUID, session_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.workspace_id == workspace_id,
            sessions.c.state == "active"
        ).values(state="closing").returning(sessions)).mappings().one_or_none()

def create_or_get_execution(workspace_id: uuid.UUID, caller_id: uuid.UUID,
                            session_id: uuid.UUID, idempotency_key: str, script: str,
                            script_sha256: str, timeout_ms: int) -> tuple[RowMapping, bool]:
    """Return (record, created); a key with different inputs is a conflict."""
    with transaction() as connection:
        # Serialize retries before checking state so a concurrent duplicate can
        # only observe and return the first durable record, never launch twice.
        connection.execute(select(func.pg_advisory_xact_lock(
            func.hashtextextended(str(caller_id) + ":" + idempotency_key, 5005))))
        existing = connection.execute(select(executions).where(
            executions.c.caller_id == caller_id,
            executions.c.idempotency_key == idempotency_key,
        ).with_for_update()).mappings().one_or_none()
        if existing is not None:
            same = (existing["workspace_id"] == workspace_id
                    and existing["session_id"] == session_id
                    and existing["script_sha256"] == script_sha256
                    and existing["script"] == script
                    and existing["timeout_ms"] == timeout_ms)
            if not same:
                raise RuntimeError("idempotency_conflict")
            return existing, False
        session = connection.execute(select(sessions).join(
            devices, devices.c.id == sessions.c.device_id).where(
            sessions.c.id == session_id, sessions.c.workspace_id == workspace_id,
            sessions.c.state == "active", devices.c.authorization_status == "active"
        ).with_for_update()).mappings().one_or_none()
        if session is None:
            raise LookupError("active_session_not_found")
        execution_id = uuid.uuid4()
        try:
            connection.execute(insert(executions).values(
                id=execution_id, workspace_id=workspace_id, session_id=session_id,
                caller_id=caller_id, idempotency_key=idempotency_key, script=script,
                script_sha256=script_sha256, timeout_ms=timeout_ms, status="queued"))
        except IntegrityError as error:
            if getattr(error.orig, "sqlstate", None) == "23505":
                raise RuntimeError("session_busy") from None
            raise
        connection.execute(insert(audit_records).values(
            id=uuid.uuid4(), workspace_id=workspace_id, caller_id=caller_id,
            action="execution.requested", resource_type="execution", resource_id=execution_id,
            script=script, script_sha256=script_sha256))
        return connection.execute(select(executions).where(
            executions.c.id == execution_id)).mappings().one(), True

def mark_execution_dispatch_requested(execution_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(update(executions).where(
            executions.c.id == execution_id,
            executions.c.status == "queued",
        ).values(dispatch_requested_at=func.coalesce(
            executions.c.dispatch_requested_at, func.now())).returning(executions)
        ).mappings().one_or_none()

def list_retryable_session_dispatches() -> list[RowMapping]:
    with transaction() as connection:
        return list(connection.execute(select(
            sessions.c.id, sessions.c.device_id,
        ).join(devices, devices.c.id == sessions.c.device_id).where(
            sessions.c.state == "starting",
            sessions.c.dispatch_requested_at.is_not(None),
            devices.c.authorization_status == "active",
        )).mappings())

def list_retryable_execution_dispatches() -> list[RowMapping]:
    with transaction() as connection:
        return list(connection.execute(select(
            executions.c.id, sessions.c.device_id,
        ).join(sessions, sessions.c.id == executions.c.session_id)
         .join(devices, devices.c.id == sessions.c.device_id).where(
            executions.c.status == "queued",
            executions.c.dispatch_requested_at.is_not(None),
            sessions.c.state == "active",
            devices.c.authorization_status == "active",
        )).mappings())

def split_utf8_chunks(value: str, limit: int = 8192) -> list[str]:
    chunks, current, size = [], [], 0
    for character in value:
        encoded_size = len(character.encode())
        if current and size + encoded_size > limit:
            chunks.append("".join(current))
            current, size = [], 0
        current.append(character)
        size += encoded_size
    if current:
        chunks.append("".join(current))
    return chunks

def _canonical_record_hash(record: dict[str, object]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()

def _uuid(value: object, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError) as error:
        raise RuntimeError("invalid_" + field) from error

def _require_fields(data: dict[str, object], fields: set[str]) -> None:
    if set(data) != fields:
        raise RuntimeError("invalid_record_fields")

def _execution_binding(connection: Connection, device_id: uuid.UUID, session_id: uuid.UUID,
                       execution_id: uuid.UUID, script_sha256: str) -> RowMapping:
    row = connection.execute(select(
        executions.c.id, executions.c.workspace_id, executions.c.caller_id,
        executions.c.status, executions.c.script_sha256, executions.c.output_complete,
        sessions.c.id.label("session_id"), sessions.c.device_id, sessions.c.state.label("session_state"),
    ).join(sessions, sessions.c.id == executions.c.session_id).where(
        executions.c.id == execution_id,
    ).with_for_update()).mappings().one_or_none()
    valid = (row is not None
             and row["device_id"] == device_id
             and row["session_id"] == session_id
             and row["script_sha256"] == script_sha256)
    if not valid:
        raise RuntimeError("ledger_binding_mismatch")
    return row

def _session_binding(connection: Connection, device_id: uuid.UUID,
                     session_id: uuid.UUID) -> RowMapping:
    row = connection.execute(select(
        sessions.c.id, sessions.c.workspace_id, sessions.c.caller_id,
        sessions.c.device_id, sessions.c.state,
    ).where(
        sessions.c.id == session_id,
    ).with_for_update()).mappings().one_or_none()
    if row is None or row["device_id"] != device_id:
        raise RuntimeError("ledger_session_binding_mismatch")
    return row

def _terminal_values(data: dict[str, object], endpoint_observed_at: datetime) -> dict[str, object]:
    state = data.get("state")
    if state not in {"completed", "timed_out", "cancelled", "outcome_unknown"}:
        raise RuntimeError("invalid_terminal_state")
    return {
        "status": state,
        "invocation_outcome": data.get("invocationOutcome"),
        "outcome_reason": data.get("outcomeReason") if state == "outcome_unknown" else None,
        "last_confirmed_status": data.get("lastConfirmedStatus") if state == "outcome_unknown" else "running",
        "exit_code": data.get("exitCode"),
        "exit_code_source": data.get("exitCodeSource"),
        "had_errors": data.get("hadErrors"),
        "stdout": None,
        "stderr": None,
        "duration_ms": data.get("durationMs"),
        "capture_truncated": data.get("captureTruncated"),
        "last_native_exit_code": data.get("lastNativeExitCode"),
        "endpoint_finished_at": endpoint_observed_at,
        "finished_at": func.now(),
    }

def _collect_output(pending: list[dict[str, object]], execution_id: uuid.UUID,
                    stream: str, text_value: str, endpoint_observed_at: datetime) -> None:
    if stream not in {"stdout", "stderr"}:
        raise RuntimeError("invalid_stream")
    for chunk in split_utf8_chunks(text_value):
        pending.append({
            "execution_id": execution_id,
            "stream": stream,
            "text": chunk,
            "byte_count": len(chunk.encode()),
            "endpoint_observed_at": endpoint_observed_at,
        })

def _bulk_insert_output(connection: Connection, pending: list[dict[str, object]]) -> None:
    if not pending:
        return
    grouped: dict[tuple[uuid.UUID, str], list[dict[str, object]]] = {}
    for row in pending:
        grouped.setdefault((row["execution_id"], row["stream"]), []).append(row)
    rows: list[dict[str, object]] = []
    for (execution_id, stream), values in grouped.items():
        next_sequence = (connection.execute(select(
            func.coalesce(func.max(execution_output_events.c.sequence), 0)
        ).where(
            execution_output_events.c.execution_id == execution_id,
            execution_output_events.c.stream == stream,
        )).scalar_one() + 1)
        for offset, value in enumerate(values):
            rows.append({
                **value,
                "sequence": next_sequence + offset,
            })
    connection.execute(insert(execution_output_events), rows)

def _apply_ledger_record(connection: Connection, device_id: uuid.UUID, record_type: str,
                         data: dict[str, object], endpoint_observed_at: datetime,
                         pending_output: list[dict[str, object]]) -> dict[str, object]:
    terminal_execution_ids: list[uuid.UUID] = []
    ready_session_ids: list[uuid.UUID] = []
    closed_session_ids: list[uuid.UUID] = []
    if record_type == "session_started":
        _require_fields(data, {"sessionId"})
        session_id = _uuid(data["sessionId"], "session_id")
        _session_binding(connection, device_id, session_id)
        changed = connection.execute(update(sessions).where(
            sessions.c.id == session_id,
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active")),
        ).values(state="active", ready_at=func.coalesce(sessions.c.ready_at, func.now()))
         .returning(sessions.c.id)).scalar_one_or_none()
        if changed is None:
            raise RuntimeError("ledger_session_binding_mismatch")
        ready_session_ids.append(session_id)
    elif record_type in {"execution_accepted", "execution_started"}:
        _require_fields(data, {"sessionId", "executionId", "scriptSha256"})
        session_id = _uuid(data["sessionId"], "session_id")
        execution_id = _uuid(data["executionId"], "execution_id")
        script_sha256 = str(data["scriptSha256"])
        row = _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
        if row["status"] not in {"queued", "running"}:
            raise RuntimeError("ledger_execution_not_live")
        values = {
            "status": "running",
            "last_confirmed_status": "accepted" if record_type == "execution_accepted" else "running",
        }
        if record_type == "execution_accepted":
            values["endpoint_accepted_at"] = endpoint_observed_at
        else:
            values["endpoint_started_at"] = endpoint_observed_at
            values["started_at"] = func.coalesce(executions.c.started_at, func.now())
        connection.execute(update(executions).where(executions.c.id == execution_id).values(**values))
    elif record_type == "output_chunk":
        _require_fields(data, {"sessionId", "executionId", "scriptSha256", "stream", "text"})
        session_id = _uuid(data["sessionId"], "session_id")
        execution_id = _uuid(data["executionId"], "execution_id")
        script_sha256 = str(data["scriptSha256"])
        _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
        _collect_output(pending_output, execution_id, str(data["stream"]), str(data["text"]), endpoint_observed_at)
    elif record_type == "output_dropped":
        _require_fields(data, {"sessionId", "executionId", "scriptSha256", "reason"})
        session_id = _uuid(data["sessionId"], "session_id")
        execution_id = _uuid(data["executionId"], "execution_id")
        script_sha256 = str(data["scriptSha256"])
        _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
        connection.execute(update(executions).where(executions.c.id == execution_id).values(
            output_complete=False, output_loss_reason=str(data["reason"])[:80], capture_truncated=True))
    elif record_type == "execution_finished":
        _require_fields(data, {"sessionId", "executionId", "scriptSha256", "state",
                               "invocationOutcome", "exitCode", "exitCodeSource", "hadErrors",
                               "durationMs", "captureTruncated", "lastNativeExitCode"})
        session_id = _uuid(data["sessionId"], "session_id")
        execution_id = _uuid(data["executionId"], "execution_id")
        script_sha256 = str(data["scriptSha256"])
        row = _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
        if row["status"] not in {"queued", "running"}:
            raise RuntimeError("ledger_execution_not_live")
        values = _terminal_values(data, endpoint_observed_at)
        if row["output_complete"] is False:
            values["capture_truncated"] = True
        changed = connection.execute(update(executions).where(
            executions.c.id == execution_id,
            executions.c.status.in_(("queued", "running")),
        ).values(**values)).rowcount
        if changed != 1:
            raise RuntimeError("invalid_execution_transition")
        terminal_execution_ids.append(execution_id)
    elif record_type == "cancellation_requested":
        _require_fields(data, {"sessionId", "executionId", "scriptSha256"})
        session_id = _uuid(data["sessionId"], "session_id")
        execution_id = _uuid(data["executionId"], "execution_id")
        script_sha256 = str(data["scriptSha256"])
        row = _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
        connection.execute(insert(audit_records).values(
            id=uuid.uuid4(), workspace_id=row["workspace_id"], caller_id=row["caller_id"],
            action="execution.cancellation_observed", resource_type="execution", resource_id=execution_id))
    elif record_type == "worker_stopped":
        _require_fields(data, {"sessionId", "executionId", "scriptSha256", "reason",
                               "cleanupConfirmed", "captureTruncated"})
        session_id = _uuid(data["sessionId"], "session_id")
        _session_binding(connection, device_id, session_id)
        execution_raw = data["executionId"]
        execution_id = None if execution_raw is None else _uuid(execution_raw, "execution_id")
        if execution_id is not None:
            script_sha256 = str(data["scriptSha256"])
            row = _execution_binding(connection, device_id, session_id, execution_id, script_sha256)
            if row["status"] in {"queued", "running"}:
                capture_truncated = bool(data["captureTruncated"]) or row["output_complete"] is False
                connection.execute(update(executions).where(
                    executions.c.id == execution_id,
                    executions.c.status.in_(("queued", "running")),
                ).values(status="outcome_unknown", outcome_reason=str(data["reason"])[:64],
                         last_confirmed_status=executions.c.status, endpoint_finished_at=endpoint_observed_at,
                         finished_at=func.now(), capture_truncated=capture_truncated,
                         output_complete=False if capture_truncated else executions.c.output_complete,
                         output_loss_reason=func.coalesce(
                             executions.c.output_loss_reason, str(data["reason"])[:80])
                         if capture_truncated else executions.c.output_loss_reason))
                terminal_execution_ids.append(execution_id)
        elif data["scriptSha256"] is not None:
            raise RuntimeError("ledger_binding_mismatch")
        if data.get("cleanupConfirmed") is True:
            connection.execute(update(sessions).where(
                sessions.c.id == session_id,
                sessions.c.device_id == device_id,
                sessions.c.state.in_(("starting", "active", "closing", "cleanup_unknown")),
            ).values(state="lost", closed_at=func.now()))
        else:
            connection.execute(update(sessions).where(
                sessions.c.id == session_id,
                sessions.c.device_id == device_id,
                sessions.c.state.in_(("starting", "active", "closing")),
            ).values(state="cleanup_unknown", closed_at=func.now()))
    elif record_type == "session_closed":
        _require_fields(data, {"sessionId"})
        session_id = _uuid(data["sessionId"], "session_id")
        _session_binding(connection, device_id, session_id)
        changed = connection.execute(update(sessions).where(
            sessions.c.id == session_id,
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active", "closing", "cleanup_unknown", "lost")),
        ).values(state="closed", closed_at=func.now()).returning(sessions.c.id)).scalar_one_or_none()
        if changed is None:
            raise RuntimeError("ledger_session_binding_mismatch")
        closed_session_ids.append(session_id)
    else:
        raise RuntimeError("invalid_record_type")
    return {
        "terminal_execution_ids": terminal_execution_ids,
        "ready_session_ids": ready_session_ids,
        "closed_session_ids": closed_session_ids,
    }

def ingest_endpoint_ledger_batch(device_id: uuid.UUID | str, ledger_id: str,
                                 records: list[dict[str, object]]) -> dict[str, object]:
    if not records:
        raise RuntimeError("empty_ledger_batch")
    device_uuid = uuid.UUID(str(device_id))
    terminal_execution_ids: list[uuid.UUID] = []
    ready_session_ids: list[uuid.UUID] = []
    closed_session_ids: list[uuid.UUID] = []
    pending_output: list[dict[str, object]] = []
    with transaction() as connection:
        owned = connection.execute(select(devices.c.id).where(
            devices.c.id == device_uuid,
        ).with_for_update()).scalar_one_or_none()
        if owned is None:
            raise RuntimeError("unknown_device")
        cursor = connection.execute(select(endpoint_ledger_cursors).where(
            endpoint_ledger_cursors.c.device_id == device_uuid).with_for_update()).mappings().one_or_none()
        if cursor is None:
            connection.execute(insert(endpoint_ledger_cursors).values(
                device_id=device_uuid, ledger_id=ledger_id, acknowledged_through=0))
            acknowledged_through = 0
        else:
            if cursor["ledger_id"] != ledger_id:
                raise RuntimeError("ledger_generation_mismatch")
            acknowledged_through = int(cursor["acknowledged_through"])
        expected = acknowledged_through + 1
        for record in records:
            sequence = int(record["sequence"])
            if sequence <= 0:
                raise RuntimeError("invalid_ledger_sequence")
            record_type = str(record["recordType"])
            endpoint_observed_at = datetime.fromisoformat(
                str(record["endpointObservedAt"]).replace("Z", "+00:00"))
            data = record["data"]
            if not isinstance(data, dict):
                raise RuntimeError("invalid_ledger_record")
            canonical = {
                "sequence": sequence,
                "recordType": record_type,
                "endpointObservedAt": endpoint_observed_at.isoformat(),
                "data": data,
            }
            record_hash = _canonical_record_hash(canonical)
            existing = connection.execute(select(endpoint_ledger_records.c.record_hash).where(
                endpoint_ledger_records.c.device_id == device_uuid,
                endpoint_ledger_records.c.ledger_id == ledger_id,
                endpoint_ledger_records.c.sequence == sequence,
            )).scalar_one_or_none()
            if existing is not None:
                if existing != record_hash:
                    raise RuntimeError("ledger_conflicting_duplicate")
                continue
            if sequence != expected:
                raise RuntimeError("ledger_gap")
            outcome = _apply_ledger_record(connection, device_uuid, record_type, data,
                                           endpoint_observed_at, pending_output)
            terminal_execution_ids.extend(outcome["terminal_execution_ids"])
            ready_session_ids.extend(outcome["ready_session_ids"])
            closed_session_ids.extend(outcome["closed_session_ids"])
            connection.execute(insert(endpoint_ledger_records).values(
                device_id=device_uuid, ledger_id=ledger_id, sequence=sequence,
                record_type=record_type, record_hash=record_hash, record=canonical,
                endpoint_observed_at=endpoint_observed_at))
            acknowledged_through = sequence
            expected = sequence + 1
        _bulk_insert_output(connection, pending_output)
        connection.execute(update(endpoint_ledger_cursors).where(
            endpoint_ledger_cursors.c.device_id == device_uuid,
        ).values(acknowledged_through=acknowledged_through, updated_at=func.now()))
    return {
        "ledger_id": ledger_id,
        "acknowledged_through": acknowledged_through,
        "terminal_execution_ids": terminal_execution_ids,
        "ready_session_ids": ready_session_ids,
        "closed_session_ids": closed_session_ids,
    }

def mark_execution_failed_to_start(execution_id: uuid.UUID, reason: str) -> None:
    with transaction() as connection:
        connection.execute(update(executions).where(
            executions.c.id == execution_id,
            executions.c.status == "queued",
        ).values(status="failed_to_start", outcome_reason=reason,
                 last_confirmed_status="queued", finished_at=func.now()))

def mark_queued_execution_cancelled(workspace_id: uuid.UUID, execution_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(update(executions).where(
            executions.c.id == execution_id,
            executions.c.workspace_id == workspace_id,
            executions.c.status == "queued",
        ).values(status="cancelled", outcome_reason="caller_cancelled_before_start",
                 last_confirmed_status="queued", finished_at=func.now()).returning(executions)).mappings().one_or_none()

def get_workspace_execution(workspace_id: uuid.UUID, execution_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(select(executions).where(
            executions.c.id == execution_id,
            executions.c.workspace_id == workspace_id)).mappings().one_or_none()

def get_execution_output_events(execution_id: uuid.UUID, stream: str, after: int,
                                limit: int) -> list[RowMapping]:
    with transaction() as connection:
        return list(connection.execute(select(
            execution_output_events.c.sequence, execution_output_events.c.text,
            execution_output_events.c.byte_count, execution_output_events.c.created_at,
        ).where(
            execution_output_events.c.execution_id == execution_id,
            execution_output_events.c.stream == stream,
            execution_output_events.c.sequence > after,
        ).order_by(execution_output_events.c.sequence).limit(limit)).mappings())

def get_execution_output_high_water(execution_id: uuid.UUID, stream: str) -> int:
    with transaction() as connection:
        return connection.execute(select(func.coalesce(func.max(execution_output_events.c.sequence), 0)).where(
            execution_output_events.c.execution_id == execution_id,
            execution_output_events.c.stream == stream)).scalar_one()

def get_execution_output_scan_events(execution_id: uuid.UUID, stream: str,
                                     high_water: int) -> list[RowMapping]:
    with transaction() as connection:
        return list(connection.execute(select(
            execution_output_events.c.sequence, execution_output_events.c.text,
            execution_output_events.c.byte_count, execution_output_events.c.created_at,
        ).where(
            execution_output_events.c.execution_id == execution_id,
            execution_output_events.c.stream == stream,
            execution_output_events.c.sequence <= high_water,
        ).order_by(execution_output_events.c.sequence).limit(MAX_QUERY_SCAN_EVENTS + 1)).mappings())

def get_execution_output_snapshot_events(execution_id: uuid.UUID, stream: str) -> tuple[int, list[RowMapping]]:
    high_water = get_execution_output_high_water(execution_id, stream)
    return high_water, get_execution_output_scan_events(execution_id, stream, high_water)

def search_execution_output(execution_id: uuid.UUID, stream: str, query: str, *,
                            case_sensitive: bool, context_lines: int,
                            limit_matches: int, after_byte: int) -> dict[str, object]:
    high_water, rows = get_execution_output_snapshot_events(execution_id, stream)
    return query_retained_output(rows, query=query, case_sensitive=case_sensitive,
                                 context_lines=context_lines, limit_matches=limit_matches,
                                 after_byte=after_byte, high_water_cursor=high_water)

def tail_execution_output(execution_id: uuid.UUID, stream: str, lines: int) -> dict[str, object]:
    high_water, rows = get_execution_output_snapshot_events(execution_id, stream)
    return tail_retained_output(rows, lines=lines, high_water_cursor=high_water)

def range_execution_output(execution_id: uuid.UUID, stream: str,
                           start_byte: int, end_byte: int) -> dict[str, object]:
    high_water, rows = get_execution_output_snapshot_events(execution_id, stream)
    return range_retained_output(rows, start_byte=start_byte, end_byte=end_byte,
                                 high_water_cursor=high_water)

def get_execution_output_page(execution_id: uuid.UUID, stream: str, after: int,
                              limit_bytes: int) -> dict[str, object]:
    rows = get_execution_output_events(execution_id, stream, after, 1000)
    text_parts, byte_total, next_cursor = [], 0, after
    for row in rows:
        if text_parts and byte_total + row["byte_count"] > limit_bytes:
            break
        if row["byte_count"] > limit_bytes:
            break
        text_parts.append(row["text"])
        byte_total += row["byte_count"]
        next_cursor = row["sequence"]
    has_more = bool(get_execution_output_events(execution_id, stream, next_cursor, 1))
    return {"text": "".join(text_parts), "next_cursor": str(next_cursor), "has_more": has_more}

def get_execution_output_preview(execution_id: uuid.UUID, stream: str, limit_bytes: int = 8192) -> dict[str, object]:
    page = get_execution_output_page(execution_id, stream, 0, limit_bytes)
    return {"text": page["text"], "shortened": page["has_more"]}

def recover_interrupted_work() -> None:
    """Resolve only work the restarted control plane provably never dispatched.

    Once a dispatch intent is durable, endpoint delivery is ambiguous. Those
    rows remain live so the endpoint ledger can replay accepted/running/terminal
    evidence after reconnect.
    """
    with transaction() as connection:
        connection.execute(update(executions).where(
            executions.c.status == "queued",
            executions.c.dispatch_requested_at.is_(None),
        ).values(status="failed_to_start", outcome_reason="control_plane_restart_before_dispatch",
                 last_confirmed_status="queued", finished_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.state == "starting",
            sessions.c.dispatch_requested_at.is_(None),
        ).values(state="failed", closed_at=func.now()))

def fail_device_investigations(device_id: uuid.UUID | str) -> list[uuid.UUID]:
    with transaction() as connection:
        authorization_status = connection.execute(select(devices.c.authorization_status).where(
            devices.c.id == device_id)).scalar_one_or_none()
        if authorization_status != "revoked":
            return []
        live_sessions = select(sessions.c.id).where(
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active", "closing")))
        affected_execution_ids = list(connection.execute(select(executions.c.id).where(
            executions.c.session_id.in_(live_sessions),
            executions.c.status.in_(("queued", "running")))).scalars())
        connection.execute(update(executions).where(
            executions.c.session_id.in_(live_sessions),
            executions.c.status.in_(("queued", "running"))).values(
            status="outcome_unknown", outcome_reason="device_revoked_cleanup_unconfirmed",
            last_confirmed_status=executions.c.status, finished_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state == "starting").values(
            state="failed", closed_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state == "closing").values(
            state="cleanup_unknown", closed_at=func.now()))
        return affected_execution_ids
