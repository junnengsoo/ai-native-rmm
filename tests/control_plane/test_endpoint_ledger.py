import uuid
from datetime import datetime, timezone

import pytest

from control_plane import database


def observed():
    return datetime.now(timezone.utc).isoformat()


def record(sequence, record_type, data):
    return {
        "sequence": sequence,
        "recordType": record_type,
        "endpointObservedAt": observed(),
        "data": data,
    }


def ledger_fixture(name):
    database.initialize()
    workspace_id, admin_id = database.create_workspace_with_admin(f"{name}-{uuid.uuid4()}", "admin-" + uuid.uuid4().hex)
    caller_id, _ = database.create_caller(workspace_id, admin_id, "operator-" + uuid.uuid4().hex,
                                          "operator", "operator-" + uuid.uuid4().hex)
    public_key = "endpoint-ledger-" + uuid.uuid4().hex
    pairing_code = uuid.uuid4().hex[:12].upper()
    database.authenticate_device(public_key, pairing_code)
    device_id = database.approve_pairing(
        database.digest(pairing_code), workspace_id, admin_id, "Ledger PC " + uuid.uuid4().hex)
    assert device_id is not None
    database.authenticate_device(public_key, "IGNORED234567")
    session = database.create_starting_session(workspace_id, caller_id, device_id)
    assert session is not None
    ledger_id = uuid.uuid4().hex
    database.ingest_endpoint_ledger_batch(device_id, ledger_id, [
        record(1, "session_started", {"sessionId": str(session["id"])})
    ])
    script = "'ok'"
    script_hash = database.digest(script)
    execution, _ = database.create_or_get_execution(workspace_id, caller_id, session["id"],
                                                    "idempotency-" + uuid.uuid4().hex,
                                                    script, script_hash, 5000)
    return {
        "workspace_id": workspace_id,
        "caller_id": caller_id,
        "device_id": device_id,
        "session_id": session["id"],
        "execution_id": execution["id"],
        "script_hash": script_hash,
        "ledger_id": ledger_id,
    }


def binding(ctx):
    return {
        "sessionId": str(ctx["session_id"]),
        "executionId": str(ctx["execution_id"]),
        "scriptSha256": ctx["script_hash"],
    }


def ingest(ctx, *records):
    return database.ingest_endpoint_ledger_batch(ctx["device_id"], ctx["ledger_id"], list(records))


def test_ledger_rejects_gaps_wrong_hashes_and_conflicting_duplicates():
    gap = ledger_fixture("ledger-gap")
    with pytest.raises(RuntimeError, match="ledger_gap"):
        ingest(gap, record(3, "execution_accepted", binding(gap)))

    wrong_hash = ledger_fixture("ledger-wrong-hash")
    bad = {**binding(wrong_hash), "scriptSha256": "0" * 64}
    with pytest.raises(RuntimeError, match="ledger_binding_mismatch"):
        ingest(wrong_hash, record(2, "execution_accepted", bad))
    row = database.get_workspace_execution(wrong_hash["workspace_id"], wrong_hash["execution_id"])
    assert row["status"] == "queued"

    duplicate = ledger_fixture("ledger-duplicate")
    accepted = record(2, "execution_accepted", binding(duplicate))
    ingest(duplicate, accepted)
    ack = ingest(duplicate, accepted)
    assert ack["acknowledged_through"] == 2
    changed = {**binding(duplicate), "scriptSha256": "f" * 64}
    with pytest.raises(RuntimeError, match="ledger_conflicting_duplicate"):
        ingest(duplicate, record(2, "execution_accepted", changed))


def test_output_dropped_marker_surfaces_in_materialized_execution_state():
    ctx = ledger_fixture("ledger-output-drop")
    base = binding(ctx)
    ingest(ctx,
           record(2, "execution_accepted", base),
           record(3, "execution_started", base),
           record(4, "output_dropped", {**base, "reason": "endpoint_ledger_capacity_exceeded"}),
           record(5, "execution_finished", {
               **base,
               "state": "completed",
               "invocationOutcome": "completed_normally",
               "exitCode": 0,
               "exitCodeSource": "normalized_invocation",
               "hadErrors": False,
               "durationMs": 1.0,
               "captureTruncated": False,
               "lastNativeExitCode": None,
           }))
    row = database.get_workspace_execution(ctx["workspace_id"], ctx["execution_id"])
    assert row["status"] == "completed"
    assert row["output_complete"] is False
    assert row["output_loss_reason"] == "endpoint_ledger_capacity_exceeded"
    assert row["capture_truncated"] is True


def test_worker_stopped_without_terminal_record_materializes_unknown_outcome():
    ctx = ledger_fixture("ledger-worker-stopped")
    base = binding(ctx)
    ingest(ctx,
           record(2, "execution_accepted", base),
           record(3, "execution_started", base),
           record(4, "worker_stopped", {
               **base,
               "reason": "endpoint_service_restart",
               "cleanupConfirmed": True,
               "captureTruncated": True,
           }))
    row = database.get_workspace_execution(ctx["workspace_id"], ctx["execution_id"])
    assert row["status"] == "outcome_unknown"
    assert row["outcome_reason"] == "endpoint_service_restart"
    assert row["last_confirmed_status"] == "running"
    assert row["capture_truncated"] is True
    assert row["output_complete"] is False
    assert row["output_loss_reason"] == "endpoint_service_restart"
    session = database.get_workspace_session(ctx["workspace_id"], ctx["session_id"])
    assert session["state"] == "lost"


def test_worker_stopped_preserves_prior_output_loss_reason():
    ctx = ledger_fixture("ledger-worker-stopped-output-loss")
    base = binding(ctx)
    ingest(ctx,
           record(2, "execution_accepted", base),
           record(3, "execution_started", base),
           record(4, "output_dropped", {**base, "reason": "endpoint_ledger_capacity_exceeded"}),
           record(5, "worker_stopped", {
               **base,
               "reason": "endpoint_service_restart",
               "cleanupConfirmed": True,
               "captureTruncated": False,
           }))
    row = database.get_workspace_execution(ctx["workspace_id"], ctx["execution_id"])
    assert row["status"] == "outcome_unknown"
    assert row["capture_truncated"] is True
    assert row["output_complete"] is False
    assert row["output_loss_reason"] == "endpoint_ledger_capacity_exceeded"


def test_worker_stopped_without_confirmed_cleanup_marks_session_cleanup_unknown():
    ctx = ledger_fixture("ledger-worker-stopped-unconfirmed")
    base = binding(ctx)
    ingest(ctx,
           record(2, "execution_accepted", base),
           record(3, "execution_started", base),
           record(4, "worker_stopped", {
               **base,
               "reason": "cleanup_unconfirmed",
               "cleanupConfirmed": False,
               "captureTruncated": True,
           }))
    row = database.get_workspace_execution(ctx["workspace_id"], ctx["execution_id"])
    assert row["status"] == "outcome_unknown"
    session = database.get_workspace_session(ctx["workspace_id"], ctx["session_id"])
    assert session["state"] == "cleanup_unknown"


def test_startup_recovery_fails_only_provably_undispatched_work():
    database.initialize()
    workspace_id, admin_id = database.create_workspace_with_admin(
        "startup-replay-" + uuid.uuid4().hex, "admin-" + uuid.uuid4().hex)
    caller_id, _ = database.create_caller(workspace_id, admin_id, "operator-" + uuid.uuid4().hex,
                                          "operator", "operator-" + uuid.uuid4().hex)
    public_key = "startup-replay-" + uuid.uuid4().hex
    pairing_code = uuid.uuid4().hex[:12].upper()
    database.authenticate_device(public_key, pairing_code)
    device_id = database.approve_pairing(
        database.digest(pairing_code), workspace_id, admin_id, "Startup PC " + uuid.uuid4().hex)
    assert device_id is not None
    database.authenticate_device(public_key, "IGNORED234567")

    starting = database.create_starting_session(workspace_id, caller_id, device_id)
    assert starting is not None
    database.recover_interrupted_work()
    assert database.get_workspace_session(workspace_id, starting["id"])["state"] == "failed"

    replayable = database.create_starting_session(workspace_id, caller_id, device_id)
    assert replayable is not None
    database.mark_session_dispatch_requested(replayable["id"])
    database.recover_interrupted_work()
    assert database.get_workspace_session(workspace_id, replayable["id"])["state"] == "starting"

    ledger_id = uuid.uuid4().hex
    database.ingest_endpoint_ledger_batch(device_id, ledger_id, [
        record(1, "session_started", {"sessionId": str(replayable["id"])})
    ])
    execution, _ = database.create_or_get_execution(
        workspace_id, caller_id, replayable["id"], "startup-undispatched-execution",
        "'ok'", database.digest("'ok'"), 5000)
    database.recover_interrupted_work()
    row = database.get_workspace_execution(workspace_id, execution["id"])
    assert row["status"] == "failed_to_start"
    assert row["outcome_reason"] == "control_plane_restart_before_dispatch"

    replayable_execution, _ = database.create_or_get_execution(
        workspace_id, caller_id, replayable["id"], "startup-replay-execution",
        "'ok'", database.digest("'ok'"), 5000)
    database.mark_execution_dispatch_requested(replayable_execution["id"])
    database.recover_interrupted_work()
    row = database.get_workspace_execution(workspace_id, replayable_execution["id"])
    assert row["status"] == "queued"
