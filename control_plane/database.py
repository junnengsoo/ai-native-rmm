"""SQLAlchemy Core schema and repositories; no ORM state is used."""
from __future__ import annotations

import hashlib
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Iterator

from alembic import command
from alembic.config import Config
from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, Float, ForeignKey, Index, Integer,
                        MetaData, String, Table, Text, UniqueConstraint, case,
                        create_engine, delete, func, inspect, insert, or_, select,
                        text, update)
from sqlalchemy.dialects.postgresql import UUID, insert as postgresql_insert
from sqlalchemy.engine import Connection, Engine, RowMapping
from sqlalchemy.exc import IntegrityError

metadata = MetaData()
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
    Column("public_key", Text, nullable=False, unique=True),
    Column("approved_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("last_seen", DateTime(timezone=True)), Column("activate_before", DateTime(timezone=True)))
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
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("ready_at", DateTime(timezone=True)), Column("closed_at", DateTime(timezone=True)),
    Column("idle_timeout_ms", Integer, nullable=False, server_default="1800000"),
    Column("last_activity_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("absolute_expires_at", DateTime(timezone=True), nullable=False, server_default=text("now() + interval '8 hours'")),
    CheckConstraint("idle_timeout_ms > 0 AND idle_timeout_ms <= 7200000", name="sessions_idle_timeout_valid"),
    CheckConstraint("state IN ('starting', 'active', 'closing', 'closed', 'failed', 'cleanup_unknown')", name="sessions_state_valid"))
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
    Column("last_native_exit_code", Integer),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("start_deadline_at", DateTime(timezone=True), nullable=False, server_default=text("now() + interval '60 seconds'")),
    Column("started_at", DateTime(timezone=True)), Column("finished_at", DateTime(timezone=True)),
    CheckConstraint("timeout_ms > 0", name="executions_timeout_positive"),
    CheckConstraint("status IN ('queued', 'running', 'completed', 'expired', 'timed_out', 'outcome_unknown')", name="executions_status_valid"),
    UniqueConstraint("caller_id", "idempotency_key", name="executions_caller_idempotency_key"))
Index("executions_one_live_per_session", executions.c.session_id, unique=True,
      postgresql_where=executions.c.status.in_(("queued", "running")))
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
    statement = select(devices.c.id, devices.c.approved_at, devices.c.last_seen,
                       devices.c.activate_before).where(devices.c.workspace_id == workspace_id)
    if after is not None:
        statement = statement.where(devices.c.id > after)
    with transaction() as connection:
        return list(connection.execute(statement.order_by(devices.c.id).limit(limit)).mappings())

def approve_pairing(code_hash: str, workspace_id: uuid.UUID) -> uuid.UUID | None:
    with transaction() as connection:
        acquire_enrollment_lock(connection)
        pending = connection.execute(delete(pairings).where(
            pairings.c.code_hash == code_hash, pairings.c.expires_at > func.now()
        ).returning(pairings.c.public_key, pairings.c.expires_at)).mappings().one_or_none()
        if pending is None:
            return None
        device_id = uuid.uuid4()
        connection.execute(insert(devices).values(id=device_id, workspace_id=workspace_id,
            public_key=pending["public_key"], activate_before=pending["expires_at"]))
        return device_id

def authenticate_device(public_key: str, pairing_code: str) -> dict[str, object]:
    with transaction() as connection:
        acquire_enrollment_lock(connection)
        device = connection.execute(select(devices).where(
            devices.c.public_key == public_key).with_for_update()).mappings().one_or_none()
        if device is not None:
            activated = connection.execute(update(devices).where(devices.c.id == device["id"],
                or_(devices.c.last_seen.is_not(None), devices.c.activate_before > func.now()))
                .values(last_seen=func.now()).returning(devices.c.id)).scalar_one_or_none()
            if activated is None:
                return {"state": "denied"}
            return {"state": "online", "device_id": str(device["id"]),
                    "heartbeat_seconds": 15, "stale_seconds": 45}
        connection.execute(delete(pairings).where(pairings.c.expires_at <= func.now()))
        if connection.execute(select(pairings.c.public_key).where(pairings.c.public_key == public_key)).first():
            return {"state": "pending"}
        if connection.execute(select(func.count()).select_from(pairings)).scalar_one() >= 1000:
            return {"state": "rate_limited"}
        connection.execute(insert(pairings).values(public_key=public_key, code_hash=digest(pairing_code),
            expires_at=func.now() + text("interval '10 minutes'")))
        return {"state": "pending", "code": pairing_code, "expires_in_seconds": 600}

def record_heartbeat(device_id: uuid.UUID | str) -> None:
    with transaction() as connection:
        connection.execute(update(devices).where(devices.c.id == device_id).values(last_seen=func.now()))

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

def expire_due_work() -> None:
    with transaction() as connection:
        now = func.now()
        connection.execute(update(executions).where(
            executions.c.status == "queued",
            executions.c.start_deadline_at <= now,
        ).values(status="expired", outcome_reason="start_deadline_exceeded",
                 last_confirmed_status="queued", finished_at=now))
        running_sessions = select(executions.c.session_id).where(
            executions.c.status == "running")
        idle_cutoff = sessions.c.last_activity_at + (sessions.c.idle_timeout_ms * text("interval '1 millisecond'"))
        connection.execute(update(sessions).where(
            sessions.c.state == "active",
            sessions.c.id.not_in(running_sessions),
            or_(sessions.c.absolute_expires_at + text("interval '10 seconds'") <= now,
                idle_cutoff + text("interval '10 seconds'") <= now),
        ).values(state="cleanup_unknown", closed_at=now))

def create_starting_session(workspace_id: uuid.UUID, caller_id: uuid.UUID,
                            device_id: uuid.UUID, idle_timeout_ms: int) -> RowMapping | None:
    session_id = uuid.uuid4()
    try:
        with transaction() as connection:
            connection.execute(update(executions).where(
                executions.c.status == "queued",
                executions.c.start_deadline_at <= func.now(),
            ).values(status="expired", outcome_reason="start_deadline_exceeded",
                     last_confirmed_status="queued", finished_at=func.now()))
            owned = connection.execute(select(devices.c.id).where(
                devices.c.id == device_id, devices.c.workspace_id == workspace_id,
                devices.c.last_seen > func.now() - text("interval '45 seconds'")
            ).with_for_update()).scalar_one_or_none()
            if owned is None:
                return None
            connection.execute(insert(sessions).values(
                id=session_id, workspace_id=workspace_id, device_id=device_id,
                caller_id=caller_id, state="starting", idle_timeout_ms=idle_timeout_ms,
                absolute_expires_at=func.now() + text("interval '8 hours'")))
            connection.execute(insert(audit_records).values(
                id=uuid.uuid4(), workspace_id=workspace_id, caller_id=caller_id,
                action="session.requested", resource_type="session", resource_id=session_id))
            return connection.execute(select(sessions).where(sessions.c.id == session_id)).mappings().one()
    except IntegrityError as error:
        if getattr(error.orig, "sqlstate", None) == "23505":
            raise RuntimeError("device_busy") from None
        raise

def mark_session_ready(session_id: uuid.UUID) -> None:
    with transaction() as connection:
        changed = connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state == "starting"
        ).values(state="active", ready_at=func.now(), last_activity_at=func.now())).rowcount
        if changed != 1:
            raise RuntimeError("invalid_session_transition")

def mark_session_failed(session_id: uuid.UUID) -> None:
    with transaction() as connection:
        connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state.in_(("starting", "active", "closing"))
        ).values(state="failed", closed_at=func.now()))

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

def mark_session_closed(session_id: uuid.UUID) -> None:
    with transaction() as connection:
        changed = connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state == "closing"
        ).values(state="closed", closed_at=func.now())).rowcount
        if changed != 1:
            raise RuntimeError("invalid_session_transition")

def mark_session_endpoint_closed(session_id: uuid.UUID) -> None:
    with transaction() as connection:
        connection.execute(update(sessions).where(
            sessions.c.id == session_id, sessions.c.state.in_(("active", "closing"))
        ).values(state="closed", closed_at=func.now()))

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
        session = connection.execute(select(sessions).where(
            sessions.c.id == session_id, sessions.c.workspace_id == workspace_id,
            sessions.c.state == "active").with_for_update()).mappings().one_or_none()
        if session is None:
            raise LookupError("active_session_not_found")
        now = connection.execute(select(func.now())).scalar_one()
        if session["absolute_expires_at"] <= now:
            connection.execute(update(sessions).where(sessions.c.id == session_id).values(
                state="closed", closed_at=func.now()))
            raise LookupError("active_session_not_found")
        if now + timedelta(milliseconds=timeout_ms) > session["absolute_expires_at"]:
            raise RuntimeError("execution_deadline_exceeds_session")
        execution_id = uuid.uuid4()
        try:
            connection.execute(insert(executions).values(
                id=execution_id, workspace_id=workspace_id, session_id=session_id,
                caller_id=caller_id, idempotency_key=idempotency_key, script=script,
                script_sha256=script_sha256, timeout_ms=timeout_ms, status="queued",
                start_deadline_at=func.now() + text("interval '60 seconds'")))
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

def claim_execution(execution_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        row = connection.execute(select(executions).where(
            executions.c.id == execution_id).with_for_update()).mappings().one_or_none()
        if row is None or row["status"] != "queued":
            return None
        if row["start_deadline_at"] <= connection.execute(select(func.now())).scalar_one():
            connection.execute(update(executions).where(
                executions.c.id == execution_id,
                executions.c.status == "queued",
            ).values(status="expired", outcome_reason="start_deadline_exceeded",
                     last_confirmed_status="queued", finished_at=func.now()))
            return None
        session = connection.execute(select(sessions).where(
            sessions.c.id == row["session_id"], sessions.c.state == "active").with_for_update()).mappings().one_or_none()
        if session is None:
            connection.execute(update(executions).where(
                executions.c.id == execution_id,
                executions.c.status == "queued",
            ).values(status="outcome_unknown", outcome_reason="session_not_active_before_dispatch",
                     last_confirmed_status="queued", finished_at=func.now()))
            return None
        if connection.execute(select(func.now())).scalar_one() + timedelta(milliseconds=row["timeout_ms"]) > session["absolute_expires_at"]:
            connection.execute(update(executions).where(
                executions.c.id == execution_id,
                executions.c.status == "queued",
            ).values(status="expired", outcome_reason="session_lifetime_exceeded_before_dispatch",
                     last_confirmed_status="queued", finished_at=func.now()))
            return None
        return connection.execute(update(executions).where(
            executions.c.id == execution_id, executions.c.status == "queued"
        ).values(status="running", started_at=func.now()).returning(executions)).mappings().one_or_none()

def finish_execution(execution_id: uuid.UUID, result: dict[str, object]) -> None:
    values = {
        "status": result["state"], "invocation_outcome": result.get("invocationOutcome"),
        "outcome_reason": "endpoint_reported_unknown" if result["state"] == "outcome_unknown" else None,
        "last_confirmed_status": "running" if result["state"] == "outcome_unknown" else None,
        "exit_code": result.get("exitCode"), "exit_code_source": result.get("exitCodeSource"),
        "had_errors": result.get("hadErrors"), "stdout": result.get("stdout"),
        "stderr": result.get("stderr"), "duration_ms": result.get("durationMs"),
        "capture_truncated": result.get("captureTruncated"),
        "last_native_exit_code": result.get("lastNativeExitCode"), "finished_at": func.now(),
    }
    with transaction() as connection:
        changed = connection.execute(update(executions).where(
            executions.c.id == execution_id, executions.c.status == "running"
        ).values(**values)).rowcount
        if changed != 1:
            raise RuntimeError("invalid_execution_transition")
        connection.execute(update(sessions).where(sessions.c.id == select(executions.c.session_id).where(
            executions.c.id == execution_id).scalar_subquery()).values(last_activity_at=func.now()))

def mark_execution_unknown(execution_id: uuid.UUID, reason: str,
                           last_confirmed_status: str) -> None:
    with transaction() as connection:
        connection.execute(update(executions).where(
            executions.c.id == execution_id,
            executions.c.status.in_(("queued", "running")),
        ).values(status="outcome_unknown", outcome_reason=reason,
                 last_confirmed_status=last_confirmed_status, finished_at=func.now()))
        connection.execute(update(sessions).where(sessions.c.id == select(executions.c.session_id).where(
            executions.c.id == execution_id).scalar_subquery()).values(last_activity_at=func.now()))

def get_workspace_execution(workspace_id: uuid.UUID, execution_id: uuid.UUID) -> RowMapping | None:
    with transaction() as connection:
        return connection.execute(select(executions).where(
            executions.c.id == execution_id,
            executions.c.workspace_id == workspace_id)).mappings().one_or_none()

def recover_interrupted_work() -> None:
    """A process restart destroys every live socket/worker claim."""
    with transaction() as connection:
        connection.execute(update(executions).where(
            executions.c.status.in_(("queued", "running"))).values(
            status="outcome_unknown", outcome_reason="control_plane_restart",
            last_confirmed_status=executions.c.status, finished_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.state.in_(("starting", "active", "closing"))).values(
            state="failed", closed_at=func.now()))

def fail_device_investigations(device_id: uuid.UUID | str) -> None:
    with transaction() as connection:
        live_sessions = select(sessions.c.id).where(
            sessions.c.device_id == device_id,
            sessions.c.state.in_(("starting", "active", "closing")))
        connection.execute(update(executions).where(
            executions.c.session_id.in_(live_sessions),
            executions.c.status.in_(("queued", "running"))).values(
            status="outcome_unknown", outcome_reason="endpoint_disconnected",
            last_confirmed_status=executions.c.status, finished_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state == "starting").values(
            state="failed", closed_at=func.now()))
        connection.execute(update(sessions).where(
            sessions.c.device_id == device_id,
            sessions.c.state == "closing").values(
            state="cleanup_unknown", closed_at=func.now()))
