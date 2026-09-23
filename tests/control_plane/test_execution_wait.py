import asyncio
import uuid

import pytest
from fastapi import HTTPException

from control_plane import app as app_module


def clear_waiters():
    app_module.terminal_waiters.clear()


def terminal_row(execution_id, workspace_id, status="running"):
    return {
        "id": execution_id,
        "workspace_id": workspace_id,
        "session_id": uuid.uuid4(),
        "caller_id": uuid.uuid4(),
        "status": status,
    }


def install_wait_fakes(monkeypatch, row, workspace_id):
    def fake_auth(authorization, required_role=None):
        assert authorization == "Bearer operator-secret"
        assert required_role == "operator"
        return {"workspace_id": workspace_id, "id": uuid.uuid4(), "role": "operator"}

    def fake_get_execution(requested_workspace_id, execution_id):
        if requested_workspace_id != row["workspace_id"] or execution_id != row["id"]:
            return None
        return row

    def fake_view(current):
        return {"execution_id": str(current["id"]), "status": current["status"]}

    monkeypatch.setattr(app_module, "authenticated_caller", fake_auth)
    monkeypatch.setattr(app_module, "get_workspace_execution", fake_get_execution)
    monkeypatch.setattr(app_module, "execution_view", fake_view)


async def _terminal_wait_ignores_intermediate_progress_and_releases_on_terminal(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    row = terminal_row(execution_id, workspace_id, "running")
    install_wait_fakes(monkeypatch, row, workspace_id)

    waiting = asyncio.create_task(app_module.wait_execution_terminal(
        execution_id, authorization="Bearer operator-secret", timeout_seconds=1,
    ))
    await asyncio.sleep(0.05)
    row["status"] = "running"
    await asyncio.sleep(0.05)
    assert waiting.done() is False

    row["status"] = "completed"
    await app_module.notify_terminal(execution_id)
    body = await asyncio.wait_for(waiting, 1)

    assert body == {"execution_id": str(execution_id), "status": "completed",
                    "terminal": True, "wait_timed_out": False}
    assert app_module.terminal_waiters == {}


def test_terminal_wait_ignores_intermediate_progress_and_releases_on_terminal(monkeypatch):
    clear_waiters()
    try:
        asyncio.run(_terminal_wait_ignores_intermediate_progress_and_releases_on_terminal(monkeypatch))
    finally:
        clear_waiters()


async def _terminal_wait_timeout_does_not_change_running_execution(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    row = terminal_row(execution_id, workspace_id, "running")
    install_wait_fakes(monkeypatch, row, workspace_id)

    body = await app_module.wait_execution_terminal(
        execution_id, authorization="Bearer operator-secret", timeout_seconds=0.01,
    )

    assert body == {"execution_id": str(execution_id), "status": "running",
                    "terminal": False, "wait_timed_out": True}
    assert row["status"] == "running"
    assert app_module.terminal_waiters == {}


def test_terminal_wait_timeout_does_not_change_running_execution(monkeypatch):
    clear_waiters()
    try:
        asyncio.run(_terminal_wait_timeout_does_not_change_running_execution(monkeypatch))
    finally:
        clear_waiters()


async def _terminal_wait_returns_existing_terminal_state_promptly(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    row = terminal_row(execution_id, workspace_id, "cancelled")
    install_wait_fakes(monkeypatch, row, workspace_id)

    body = await app_module.wait_execution_terminal(
        execution_id, authorization="Bearer operator-secret", timeout_seconds=20,
    )

    assert body["terminal"] is True
    assert body["wait_timed_out"] is False
    assert body["status"] == "cancelled"
    assert app_module.terminal_waiters == {}


def test_terminal_wait_returns_existing_terminal_state_promptly(monkeypatch):
    clear_waiters()
    try:
        asyncio.run(_terminal_wait_returns_existing_terminal_state_promptly(monkeypatch))
    finally:
        clear_waiters()


async def _terminal_wait_is_workspace_scoped(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    row = terminal_row(execution_id, uuid.uuid4(), "completed")
    install_wait_fakes(monkeypatch, row, workspace_id)

    with pytest.raises(HTTPException) as caught:
        await app_module.wait_execution_terminal(
            execution_id, authorization="Bearer operator-secret", timeout_seconds=0,
        )

    assert caught.value.status_code == 404
    assert app_module.terminal_waiters == {}


def test_terminal_wait_is_workspace_scoped(monkeypatch):
    clear_waiters()
    try:
        asyncio.run(_terminal_wait_is_workspace_scoped(monkeypatch))
    finally:
        clear_waiters()


async def _endpoint_disconnect_does_not_finalize_or_wake_terminal_wait(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    device_id = uuid.uuid4()
    row = terminal_row(execution_id, workspace_id, "running")
    install_wait_fakes(monkeypatch, row, workspace_id)

    def fake_fail_device_investigations(disconnected_device_id):
        assert disconnected_device_id == device_id
        return []

    monkeypatch.setattr(app_module, "fail_device_investigations", fake_fail_device_investigations)

    waiting = asyncio.create_task(app_module.wait_execution_terminal(
        execution_id, authorization="Bearer operator-secret", timeout_seconds=0.1,
    ))
    for _ in range(20):
        if str(execution_id) in app_module.terminal_waiters:
            break
        await asyncio.sleep(0.01)
    assert str(execution_id) in app_module.terminal_waiters

    await app_module.fail_device_investigations_and_notify(device_id)
    assert waiting.done() is False
    body = await asyncio.wait_for(waiting, 1)

    assert body == {"execution_id": str(execution_id), "status": "running",
                    "terminal": False, "wait_timed_out": True}
    assert app_module.terminal_waiters == {}


def test_endpoint_disconnect_does_not_finalize_or_wake_terminal_wait(monkeypatch):
    clear_waiters()
    try:
        asyncio.run(_endpoint_disconnect_does_not_finalize_or_wake_terminal_wait(monkeypatch))
    finally:
        clear_waiters()


async def _dispatch_retry_keeps_reconciliation_pending_work_live(monkeypatch):
    execution_id = uuid.uuid4()
    session_id = uuid.uuid4()
    device_id = uuid.uuid4()
    row = {
        "id": execution_id,
        "session_id": session_id,
        "script": "'ok'",
        "script_sha256": "a" * 64,
        "timeout_ms": 5000,
    }
    attempts = 0
    sent = []

    def fake_mark_dispatch(requested_execution_id):
        nonlocal attempts
        assert requested_execution_id == execution_id
        attempts += 1
        return row if attempts <= 2 else None

    class Channel:
        async def send(self, message):
            sent.append(message)

    async def fake_connected_channel(requested_device_id):
        assert requested_device_id == str(device_id)
        return Channel()

    monkeypatch.setattr(app_module, "mark_execution_dispatch_requested", fake_mark_dispatch)
    monkeypatch.setattr(app_module.endpoint_agents, "get_connected_channel", fake_connected_channel)

    await app_module.send_execution_command(execution_id, str(device_id), retry_seconds=0.001)

    assert attempts == 3
    assert [message["executionId"] for message in sent] == [str(execution_id), str(execution_id)]
    assert all(message["sessionId"] == str(session_id) for message in sent)


def test_dispatch_retry_keeps_reconciliation_pending_work_live(monkeypatch):
    asyncio.run(_dispatch_retry_keeps_reconciliation_pending_work_live(monkeypatch))


async def _session_dispatch_retry_keeps_starting_session_live(monkeypatch):
    session_id = uuid.uuid4()
    device_id = uuid.uuid4()
    row = {"id": session_id, "device_id": device_id}
    attempts = 0
    sent = []

    def fake_mark_session_dispatch(requested_session_id):
        nonlocal attempts
        assert requested_session_id == session_id
        attempts += 1
        return row if attempts <= 2 else None

    class Channel:
        async def send(self, message):
            sent.append(message)

    async def fake_connected_channel(requested_device_id):
        assert requested_device_id == str(device_id)
        return Channel()

    monkeypatch.setattr(app_module, "mark_session_dispatch_requested", fake_mark_session_dispatch)
    monkeypatch.setattr(app_module.endpoint_agents, "get_connected_channel", fake_connected_channel)

    await app_module.send_session_open_command(session_id, str(device_id), retry_seconds=0.001)

    assert attempts == 3
    assert [message["sessionId"] for message in sent] == [str(session_id), str(session_id)]
    assert all(message["type"] == "open_session" for message in sent)


def test_session_dispatch_retry_keeps_starting_session_live(monkeypatch):
    asyncio.run(_session_dispatch_retry_keeps_starting_session_live(monkeypatch))


async def _startup_restarts_durable_dispatch_retries(monkeypatch):
    session_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    device_id = uuid.uuid4()
    restarted_sessions = []
    restarted_executions = []

    def fake_sessions():
        return [{"id": session_id, "device_id": device_id}]

    def fake_executions():
        return [{"id": execution_id, "device_id": device_id}]

    async def fake_session_retry(restarted_session_id, restarted_device_id):
        restarted_sessions.append((restarted_session_id, restarted_device_id))

    async def fake_execution_retry(restarted_execution_id, restarted_device_id):
        restarted_executions.append((restarted_execution_id, restarted_device_id))

    monkeypatch.setattr(app_module, "list_retryable_session_dispatches", fake_sessions)
    monkeypatch.setattr(app_module, "list_retryable_execution_dispatches", fake_executions)
    monkeypatch.setattr(app_module, "send_session_open_command", fake_session_retry)
    monkeypatch.setattr(app_module, "send_execution_command", fake_execution_retry)

    await app_module.restart_durable_dispatch_retries()
    await asyncio.sleep(0)

    assert restarted_sessions == [(session_id, str(device_id))]
    assert restarted_executions == [(execution_id, str(device_id))]


def test_startup_restarts_durable_dispatch_retries(monkeypatch):
    asyncio.run(_startup_restarts_durable_dispatch_retries(monkeypatch))
