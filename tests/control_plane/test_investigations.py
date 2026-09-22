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
from datetime import datetime, timedelta, timezone

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
                    assert message["idleTimeoutMs"] <= 7200000
                    assert message["absoluteDeadlineUnixMs"] > int(time.time() * 1000)
                    variable = None
                    socket.send(json.dumps({"type": "session_ready", **common}))
                elif message["type"] == "close_session":
                    variable = None
                    socket.send(json.dumps({"type": "session_closed", **common}))
                elif message["type"] == "execute":
                    execution = message["executionId"]
                    assert hashlib.sha256(message["script"].encode()).hexdigest() == message["scriptSha256"]
                    assert message["startDeadlineUnixMs"] > int(time.time() * 1000)
                    socket.send(json.dumps({"type": "running", **common, "executionId": execution}))
                    if message["script"] == "$trialValue = 42":
                        variable, stdout = 42, ""
                    elif message["script"] == "$trialValue":
                        stdout = str(variable)
                    elif message["script"] == "MARK_ONCE":
                        self.marker_count += 1
                        stdout = "marked"
                    else:
                        stdout = "ok"
                    socket.send(json.dumps({
                        "type": "result", **common, "executionId": execution,
                        "state": "completed", "invocationOutcome": "completed_normally",
                        "exitCode": 0, "exitCodeSource": "normalized_invocation",
                        "hadErrors": False, "stdout": stdout, "stderr": "",
                        "durationMs": 1.0, "captureTruncated": False, "lastNativeExitCode": None,
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


def test_deadline_defaults_and_offline_outcomes_are_truthful():
    admin = bootstrap_admin()
    operator, _ = create_operator(admin, "deadline-agent")
    key, public, device = enroll(admin)
    with EndpointAgentSimulator(key, public):
        opened = httpx.post(BASE + "/sessions", headers=operator, json={"device_id": device})
        assert opened.status_code == 201
        session = opened.json()
        assert session["idle_timeout_ms"] == 1800000
        remaining = datetime.fromisoformat(session["absolute_expires_at"]) - datetime.now(timezone.utc)
        assert timedelta(hours=7, minutes=55) < remaining <= timedelta(hours=8, minutes=1)
        submitted = httpx.post(BASE + f"/sessions/{session['session_id']}/executions", headers={
            **operator, "Idempotency-Key": "default-runtime",
        }, json={"script": "'ok'"})
        assert submitted.status_code == 202
        result = wait_for_execution(operator, submitted.json()["execution_id"])
        assert result["status"] == "completed"

    offline = httpx.post(BASE + f"/sessions/{session['session_id']}/executions", headers={
        **operator, "Idempotency-Key": "offline",
    }, json={"script": "'must-not-run'", "timeout_ms": 5000})
    assert offline.status_code == 202
    result = wait_for_execution(operator, offline.json()["execution_id"])
    assert result["status"] == "outcome_unknown"
    assert result["outcome_reason"] == "device_offline_before_dispatch"
    assert result["last_confirmed_status"] == "queued"


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


def test_operator_cannot_admin_and_resources_are_workspace_scoped():
    first_admin, second_admin = bootstrap_admin(), bootstrap_admin()
    operator, _ = create_operator(first_admin)
    other_operator, _ = create_operator(second_admin)
    assert httpx.get(BASE + "/devices", headers=operator).status_code == 403
    assert httpx.post(BASE + "/callers", headers=operator, json={"name": "x", "role": "operator"}).status_code == 403
    key, public, device = enroll(first_admin)
    with EndpointAgentSimulator(key, public):
        assert httpx.post(BASE + "/sessions", headers=other_operator, json={"device_id": device}).status_code == 404
