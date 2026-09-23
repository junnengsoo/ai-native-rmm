"""Device authorization can be durably revoked without deleting history."""
import base64
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect


BASE = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")


def local_admin():
    result = subprocess.run(
        [sys.executable, "-m", "control_plane.setup", "Revocation Trial"],
        capture_output=True, text=True, check=True,
    )
    return {"Authorization": "Bearer " + result.stdout.strip()}


def operator(admin):
    response = httpx.post(BASE + "/callers", headers=admin, json={
        "name": "revocation-operator", "role": "operator",
    })
    response.raise_for_status()
    return {"Authorization": "Bearer " + response.json()["api_key"]}


def endpoint_key():
    key = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )).decode()
    return key, public


def prove(socket, key, public):
    challenge = json.loads(socket.recv())
    signature = key.sign(
        ("rmm-reachability-v1\n" + challenge["nonce"]).encode(),
        ec.ECDSA(hashes.SHA256()),
    )
    socket.send(json.dumps({
        "public_key": public,
        "signature": base64.b64encode(signature).decode(),
    }))
    return json.loads(socket.recv())


def recv_command(socket, timeout=None):
    while True:
        raw = socket.recv(timeout=timeout) if timeout is not None else socket.recv()
        message = json.loads(raw)
        if message["type"] in {"heartbeat_ack", "ledger_ack"}:
            continue
        return message


def ledger_sender():
    ledger_id = "revocation-ledger-" + uuid.uuid4().hex
    sequence = 0

    def send(socket, device_id, records):
        nonlocal sequence
        payload = []
        for record_type, data in records:
            sequence += 1
            payload.append({
                "sequence": sequence,
                "recordType": record_type,
                "endpointObservedAt": "2026-09-22T00:00:00Z",
                "data": data,
            })
        socket.send(json.dumps({
            "type": "ledger_batch",
            "deviceId": device_id,
            "ledgerId": ledger_id,
            "records": payload,
        }))
    return send


def approve(admin):
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        pending = prove(socket, key, public)
    response = httpx.post(BASE + "/pairings/approve", headers=admin, json={
        "code": pending["code"], "device_name": "Revocation PC " + pending["code"],
    })
    response.raise_for_status()
    return response.json()["device_id"], key, public


def test_offline_revocation_is_authorized_scoped_idempotent_and_permanent():
    admin = local_admin()
    other_admin = local_admin()
    caller = operator(admin)
    device, key, public = approve(admin)
    url = BASE + f"/devices/{device}/revoke"

    assert httpx.post(url).status_code == 401
    assert httpx.post(url, headers=caller).status_code == 403
    assert httpx.post(url, headers=other_admin).status_code == 404

    revoked = httpx.post(url, headers=admin)
    assert revoked.status_code == 200
    body = revoked.json()
    assert body["device_id"] == device
    assert body["authorization_status"] == "revoked"
    assert body["revoked_at"] and body["revoked_by"]
    assert body["cleanup"] == "not_required"

    listed = httpx.get(BASE + "/devices", headers=admin).json()["devices"]
    row = next(item for item in listed if item["id"] == device)
    assert row["authorization_status"] == "revoked"
    assert row["revoked_at"] == body["revoked_at"]
    assert row["revoked_by"] == body["revoked_by"]
    assert row["reachability"] == "awaiting_activation"

    denied_session = httpx.post(BASE + "/sessions", headers=caller, json={"device_id": device})
    assert denied_session.status_code == 409
    assert denied_session.json() == {"detail": "device_revoked"}

    repeated = httpx.post(url, headers=admin)
    assert repeated.status_code == 200
    assert repeated.json()["cleanup"] == "already_revoked"
    assert repeated.json()["revoked_at"] == body["revoked_at"]
    assert repeated.json()["revoked_by"] == body["revoked_by"]

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public) == {"state": "denied"}


def test_connected_revocation_closes_a_live_session_and_preserves_its_record():
    admin = local_admin()
    caller = operator(admin)
    device, key, public = approve(admin)
    endpoint_ready = threading.Event()

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public)["state"] == "online"
        send_ledger = ledger_sender()

        def endpoint_peer():
            opened = recv_command(socket)
            assert opened["type"] == "open_session" and opened["deviceId"] == device
            send_ledger(socket, device, [
                ("session_started", {"sessionId": opened["sessionId"]}),
            ])
            endpoint_ready.set()
            closed = recv_command(socket)
            assert closed == {
                "type": "close_session", "deviceId": device,
                "sessionId": opened["sessionId"],
            }
            send_ledger(socket, device, [
                ("session_closed", {"sessionId": opened["sessionId"]}),
            ])
            try:
                socket.recv()
            except ConnectionClosed:
                pass

        with ThreadPoolExecutor(1) as pool:
            peer = pool.submit(endpoint_peer)
            opened = httpx.post(BASE + "/sessions", headers=caller, json={"device_id": device})
            opened.raise_for_status()
            assert endpoint_ready.wait(5)
            session = opened.json()["session_id"]

            revoked = httpx.post(BASE + f"/devices/{device}/revoke", headers=admin, timeout=35)
            revoked.raise_for_status()
            assert revoked.json()["cleanup"] == "confirmed"
            peer.result(timeout=5)

    retained = httpx.get(BASE + f"/sessions/{session}", headers=caller)
    retained.raise_for_status()
    assert retained.json()["status"] == "closed"

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public) == {"state": "denied"}


def test_unconfirmed_revocation_cleanup_is_reported_as_unknown_without_waiting_for_timeout():
    admin = local_admin()
    caller = operator(admin)
    device, key, public = approve(admin)
    execution_started = threading.Event()

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public)["state"] == "online"
        send_ledger = ledger_sender()

        def endpoint_peer():
            opened = recv_command(socket)
            send_ledger(socket, device, [
                ("session_started", {"sessionId": opened["sessionId"]}),
            ])
            executed = recv_command(socket)
            binding = {
                "sessionId": opened["sessionId"],
                "executionId": executed["executionId"],
                "scriptSha256": executed["scriptSha256"],
            }
            send_ledger(socket, device, [
                ("execution_accepted", binding),
                ("execution_started", binding),
            ])
            execution_started.set()
            assert recv_command(socket)["type"] == "close_session"
            socket.close()

        with ThreadPoolExecutor(1) as pool:
            peer = pool.submit(endpoint_peer)
            opened = httpx.post(BASE + "/sessions", headers=caller, json={"device_id": device})
            opened.raise_for_status()
            submitted = httpx.post(
                BASE + f"/sessions/{opened.json()['session_id']}/executions",
                headers={**caller, "Idempotency-Key": "revocation-unconfirmed"},
                json={"script": "Start-Sleep 60", "timeout_ms": 60_000},
            )
            submitted.raise_for_status()
            assert execution_started.wait(5)

            started = time.monotonic()
            revoked = httpx.post(BASE + f"/devices/{device}/revoke", headers=admin, timeout=10)
            assert time.monotonic() - started < 10
            revoked.raise_for_status()
            assert revoked.json()["cleanup"] == "unconfirmed"
            peer.result(timeout=5)

    result = httpx.get(
        BASE + f"/executions/{submitted.json()['execution_id']}/wait",
        headers=caller, params={"timeout_seconds": 1},
    )
    result.raise_for_status()
    assert result.json()["status"] == "outcome_unknown"
    assert result.json()["outcome_reason"] == "device_revoked_cleanup_unconfirmed"
