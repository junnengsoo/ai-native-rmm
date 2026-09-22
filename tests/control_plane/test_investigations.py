"""Public investigation API behavior; real PostgreSQL and an independent endpoint agent."""
import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.sync.client import connect


BASE = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")


def bootstrap_admin():
    created = subprocess.run(
        [sys.executable, "-m", "control_plane.setup", "Investigation test"],
        capture_output=True, text=True, check=True,
    )
    return {"Authorization": "Bearer " + created.stdout.strip()}


def create_operator(admin, name="diagnostic-agent"):
    response = httpx.post(BASE + "/callers", headers=admin, json={"name": name, "role": "operator"})
    assert response.status_code == 201
    body = response.json()
    assert body["caller_id"] and body["api_key"].startswith("rmm_") and body["role"] == "operator"
    return {"Authorization": "Bearer " + body["api_key"]}, body["caller_id"]


def endpoint_key():
    key = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return key, public


def prove(socket, key, public):
    challenge = json.loads(socket.recv())
    signature = key.sign(
        ("rmm-reachability-v1\n" + challenge["nonce"]).encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    socket.send(json.dumps({"public_key": public, "signature": base64.b64encode(signature).decode()}))
    return json.loads(socket.recv())


def enroll(admin):
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        pending = prove(socket, key, public)
    approved = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": pending["code"]})
    assert approved.status_code == 200
    return key, public, approved.json()["device_id"]


class EndpointAgentSimulator:
    """Independent endpoint agent with one persistent PowerShell-like variable."""
    def __init__(self, key, public):
        self.key, self.public = key, public
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.marker_count = 0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        assert self.ready.wait(5)
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(5)

    def _run(self):
        variable = None
        with connect(BASE.replace("http", "ws") + "/agent") as socket:
            online = prove(socket, self.key, self.public)
            device = online["device_id"]
            self.ready.set()
            while not self.stop.is_set():
                try:
                    message = json.loads(socket.recv(timeout=0.2))
                except TimeoutError:
                    continue
                if message["type"] == "heartbeat_ack":
                    continue
                common = {"deviceId": device, "sessionId": message["sessionId"]}
                if message["type"] == "open_session":
                    variable = None
                    socket.send(json.dumps({"type": "session_ready", **common}))
                elif message["type"] == "close_session":
                    variable = None
                    socket.send(json.dumps({"type": "session_closed", **common}))
                elif message["type"] == "execute":
                    execution = message["executionId"]
                    assert hashlib.sha256(message["script"].encode()).hexdigest() == message["scriptSha256"]
                    socket.send(json.dumps({"type": "running", **common, "executionId": execution}))
                    if message["script"] == "WAIT_FOR_CANCEL":
                        while True:
                            followup = json.loads(socket.recv(timeout=2))
                            if followup["type"] == "cancel_execution" and followup["executionId"] == execution:
                                socket.send(json.dumps({
                                    "type": "result", **common, "executionId": execution,
                                    "state": "cancelled", "invocationOutcome": "stopped",
                                    "exitCode": None, "exitCodeSource": None,
                                    "hadErrors": False, "durationMs": 1.0,
                                    "captureTruncated": False, "lastNativeExitCode": None,
                                }))
                                break
                        continue
                    elif message["script"] == "$trialValue = 42":
                        variable = 42
                    elif message["script"] == "$trialValue":
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": str(variable)}))
                    elif message["script"] == "PROGRESSIVE_OUTPUT":
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": "first\n"}))
                        time.sleep(0.2)
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stderr", "text": "{\"type\":\"result\"}\n"}))
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": "snowman ☃\n"}))
                    elif message["script"] == "LONG_OUTPUT":
                        chunk = "α" * 5000 + "\n"
                        for _ in range(10):
                            socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                    "stream": "stdout", "text": chunk}))
                    elif message["script"] == "MEG_OUTPUT":
                        chunk = "m" * 8192
                        for _ in range(128):
                            socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                    "stream": "stdout", "text": chunk}))
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": "tail-after-meg"}))
                    elif message["script"] == "EMPTY_OUTPUT":
                        pass
                    elif message["script"] == "MARK_ONCE":
                        self.marker_count += 1
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": "marked"}))
                    else:
                        socket.send(json.dumps({"type": "output", **common, "executionId": execution,
                                                "stream": "stdout", "text": "ok"}))
                    socket.send(json.dumps({
                        "type": "result", **common, "executionId": execution,
                        "state": "completed", "invocationOutcome": "completed_normally",
                        "exitCode": 0, "exitCodeSource": "normalized_invocation",
                        "hadErrors": False, "durationMs": 1.0, "captureTruncated": False,
                        "lastNativeExitCode": None,
                    }))


def wait_for_execution(operator, execution_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = httpx.get(BASE + f"/executions/{execution_id}", headers=operator)
        assert response.status_code == 200
        if response.json()["status"] not in ("queued", "running"):
            return response.json()
        time.sleep(0.05)
    raise AssertionError("execution did not finish")


def submit(operator, session, script, key):
    return httpx.post(
        BASE + f"/sessions/{session}/executions", headers={**operator, "Idempotency-Key": key},
        json={"script": script, "timeout_ms": 5000},
    )


def test_timeout_is_required_and_offline_submission_fails_to_start():
    admin = bootstrap_admin()
    operator, _ = create_operator(admin, "deadline-agent")
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public):
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201
        session = opened.json()
        missing_timeout = httpx.post(BASE + f"/sessions/{session['session_id']}/executions", headers={
            **operator, "Idempotency-Key": "missing-timeout",
        }, json={"script": "'ok'"})
        assert missing_timeout.status_code == 422
        submitted = httpx.post(BASE + f"/sessions/{session['session_id']}/executions", headers={
            **operator, "Idempotency-Key": "selected-timeout",
        }, json={"script": "'ok'", "timeout_ms": 5000})
        assert submitted.status_code == 202
        result = wait_for_execution(operator, submitted.json()["execution_id"])
        assert result["status"] == "completed"

    offline = httpx.post(BASE + f"/sessions/{session['session_id']}/executions", headers={
        **operator, "Idempotency-Key": "offline",
    }, json={"script": "'must-not-run'", "timeout_ms": 5000})
    assert offline.status_code == 202
    result = wait_for_execution(operator, offline.json()["execution_id"])
    assert result["status"] == "failed_to_start"
    assert result["outcome_reason"] == "device_offline_before_dispatch"
    assert result["last_confirmed_status"] == "queued"


def test_caller_can_cancel_running_execution():
    admin = bootstrap_admin()
    operator, _ = create_operator(admin, "cancel-agent")
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public):
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201
        session = opened.json()["session_id"]
        submitted = submit(operator, session, "WAIT_FOR_CANCEL", "cancel-me")
        assert submitted.status_code == 202
        execution = submitted.json()["execution_id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            running = httpx.get(BASE + f"/executions/{execution}", headers=operator).json()
            if running["status"] == "running":
                break
            time.sleep(0.05)
        cancelled = httpx.post(BASE + f"/executions/{execution}/cancel", headers=operator)
        assert cancelled.status_code == 202
        result = wait_for_execution(operator, execution)
        assert result["status"] == "cancelled"
        assert result["invocation_outcome"] == "stopped"
        assert result["exit_code"] is None


def test_close_without_endpoint_confirmation_blocks_replacement():
    admin = bootstrap_admin()
    operator, _ = create_operator(admin, "cleanup-agent")
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public):
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201
        session = opened.json()["session_id"]
    closed = httpx.post(BASE + f"/sessions/{session}/close", headers=operator)
    assert closed.status_code == 503
    with EndpointAgentSimulator(key, public):
        assert httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device}).status_code == 409


def test_operator_runs_persistent_investigation_and_idempotent_retry_once():
    admin = bootstrap_admin()
    operator, caller_id = create_operator(admin)
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public) as endpoint:
        denied = httpx.post(BASE + "/sessions", headers=admin, json={"device_id": device})
        assert denied.status_code == 403
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201 and opened.json()["status"] == "active"
        session = opened.json()["session_id"]

        first = submit(operator, session, "$trialValue = 42", "set-value")
        assert first.status_code == 202
        assert wait_for_execution(operator, first.json()["execution_id"])["caller_id"] == caller_id
        read = submit(operator, session, "$trialValue", "read-value")
        result = wait_for_execution(operator, read.json()["execution_id"])
        assert result["stdout"] == "42" and result["exit_code"] == 0
        assert result["exit_code_source"] == "normalized_invocation"

        marker = submit(operator, session, "MARK_ONCE", "marker-once")
        retry = submit(operator, session, "MARK_ONCE", "marker-once")
        assert retry.status_code == 202 and retry.json()["execution_id"] == marker.json()["execution_id"]
        conflict = submit(operator, session, "different", "marker-once")
        assert conflict.status_code == 409
        wait_for_execution(operator, marker.json()["execution_id"])
        assert endpoint.marker_count == 1

        closed = httpx.post(BASE + f"/sessions/{session}/close", headers=operator)
        assert closed.status_code == 200 and closed.json()["status"] == "closed"
        fresh = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert fresh.status_code == 201 and fresh.json()["session_id"] != session
        fresh_read = submit(operator, fresh.json()["session_id"], "$trialValue", "fresh-read")
        assert wait_for_execution(operator, fresh_read.json()["execution_id"])["stdout"] == "None"


def test_execution_output_preview_pages_and_long_poll_are_bounded_and_scoped():
    admin = bootstrap_admin()
    other_admin = bootstrap_admin()
    operator, _ = create_operator(admin)
    other_operator, _ = create_operator(other_admin)
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public):
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201
        session = opened.json()["session_id"]

        submitted = submit(operator, session, "PROGRESSIVE_OUTPUT", "progressive")
        assert submitted.status_code == 202
        execution = submitted.json()["execution_id"]
        first_poll = httpx.get(
            BASE + f"/executions/{execution}/output/stdout/events",
            headers=operator, params={"after": "0", "wait_ms": 2000}, timeout=5,
        )
        assert first_poll.status_code == 200
        first = first_poll.json()
        assert first["events"][0]["text"] == "first\n"
        assert first["next_cursor"] != "0"
        assert first["gap"] == {"detected": False, "reason": None}
        assert first["status"] in ("running", "completed")
        assert first["terminal"] in (False, True)
        assert first["high_water_cursor"] != "0"

        resumed = httpx.get(
            BASE + f"/executions/{execution}/output/stdout/events",
            headers=operator, params={"after": first["next_cursor"], "wait_ms": 2000},
        )
        assert resumed.status_code == 200
        assert resumed.json()["events"][0]["text"] == "snowman ☃\n"
        assert resumed.json()["unicode"] == {
            "encoding": "utf-8", "ordering": "per-stream insertion order", "unit": "cursored event text",
        }

        result = wait_for_execution(operator, execution)
        assert result["output_preview"]["stdout"]["text"] == "first\nsnowman ☃\n"
        assert result["output_preview"]["stdout"]["shortened"] is False
        assert result["capture"]["loss_detected"] is False
        assert result["stdout"] == result["output_preview"]["stdout"]["text"]
        assert result["stderr"] == result["output_preview"]["stderr"]["text"] == "{\"type\":\"result\"}\n"

        stderr_events = httpx.get(
            BASE + f"/executions/{execution}/output/stderr/events",
            headers=operator, params={"after": "0"},
        ).json()["events"]
        assert stderr_events[0]["text"] == "{\"type\":\"result\"}\n"

        long = submit(operator, session, "LONG_OUTPUT", "long-output")
        assert long.status_code == 202
        long_id = long.json()["execution_id"]
        long_result = wait_for_execution(operator, long_id)
        preview = long_result["output_preview"]["stdout"]
        assert len(preview["text"].encode()) <= 8192
        assert preview["shortened"] is True
        assert preview["capture_lost"] is False

        page = httpx.get(
            BASE + f"/executions/{long_id}/output/stdout",
            headers=operator, params={"after": "0", "limit_bytes": 65536},
        )
        assert page.status_code == 200
        body = page.json()
        assert 0 < len(body["text"].encode()) <= 65536
        assert body["next_cursor"] != "0"
        assert body["has_more"] is True
        assert body["capture_lost"] is False
        assert "α" in body["text"]
        invalid = httpx.get(
            BASE + f"/executions/{long_id}/output/stdout",
            headers=operator, params={"after": "not-a-cursor"},
        )
        assert invalid.status_code == 422

        second = httpx.get(
            BASE + f"/executions/{long_id}/output/stdout",
            headers=operator, params={"after": body["next_cursor"], "limit_bytes": 65536},
        ).json()
        assert second["text"]
        assert second["gap"]["detected"] is False

        meg = submit(operator, session, "MEG_OUTPUT", "meg-output")
        assert meg.status_code == 202
        meg_id = meg.json()["execution_id"]
        meg_result = wait_for_execution(operator, meg_id)
        assert meg_result["output_preview"]["stdout"]["shortened"] is True
        assert meg_result["capture"]["loss_detected"] is False
        after_meg = httpx.get(
            BASE + f"/executions/{meg_id}/output/stdout/events",
            headers=operator, params={"after": "128", "limit": 1},
        ).json()
        assert after_meg["events"][0]["text"] == "tail-after-meg"
        assert after_meg["gap"]["detected"] is False

        assert httpx.get(BASE + f"/executions/{execution}/output/stdout", headers=other_operator).status_code == 404
        denied = httpx.get(BASE + f"/executions/{execution}/output/stdout/events", headers=other_operator)
        assert denied.status_code == 404

        empty = submit(operator, session, "EMPTY_OUTPUT", "empty-output")
        assert empty.status_code == 202
        empty_id = empty.json()["execution_id"]
        assert wait_for_execution(operator, empty_id)["output_preview"]["stdout"]["text"] == ""
        empty_poll = httpx.get(
            BASE + f"/executions/{empty_id}/output/stdout/events",
            headers=operator, params={"after": "0", "wait_ms": 50},
        ).json()
        assert empty_poll["events"] == []
        assert empty_poll["status"] == "completed"
        assert empty_poll["terminal"] is True
        assert empty_poll["no_change"] is True
        assert empty_poll["timed_out"] is False


def test_operator_cannot_admin_and_resources_are_workspace_scoped():
    first_admin, second_admin = bootstrap_admin(), bootstrap_admin()
    operator, _ = create_operator(first_admin)
    other_operator, _ = create_operator(second_admin)
    assert httpx.get(BASE + "/devices", headers=operator).status_code == 403
    assert httpx.post(BASE + "/callers", headers=operator, json={"name": "x", "role": "operator"}).status_code == 403
    key, public, device = enroll(first_admin)
    with EndpointAgentSimulator(key, public):
        assert httpx.post(BASE + "/sessions", headers=other_operator, json={"device_id": device}).status_code == 404
