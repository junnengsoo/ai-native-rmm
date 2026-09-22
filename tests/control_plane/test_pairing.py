"""Public HTTP/WSS behavior; real PostgreSQL, no private database assertions."""
import os
import subprocess
import sys
import base64
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from websockets.sync.client import connect
from websockets.exceptions import InvalidStatus
import pytest

BASE = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")


def local_admin():
    result = subprocess.run([sys.executable, "-m", "control_plane.setup", "Trial"], capture_output=True, text=True, check=True)
    return {"Authorization": "Bearer " + result.stdout.strip()}


def endpoint_key():
    key = ec.generate_private_key(ec.SECP256R1())
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    return key, public


def prove(socket, key, public):
    challenge = json.loads(socket.recv())
    assert challenge["type"] == "challenge"
    signature = key.sign(("rmm-reachability-v1\n" + challenge["nonce"]).encode(), ec.ECDSA(hashes.SHA256()))
    socket.send(json.dumps({"public_key": public, "signature": base64.b64encode(signature).decode()}))
    return json.loads(socket.recv())


def test_local_setup_reveals_credential_once_and_protects_device_listing():
    setup = subprocess.run(
        [sys.executable, "-m", "control_plane.setup", "Trial"],
        capture_output=True, text=True, check=True,
    )
    credential = setup.stdout.strip()
    assert credential.startswith("rmm_")
    base = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")
    assert httpx.get(base + "/devices").status_code == 401
    assert httpx.get(base + "/devices", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = httpx.get(base + "/devices", headers={"Authorization": "Bearer " + credential})
    assert response.status_code == 200
    assert response.json() == {"devices": [], "next_cursor": None}


def test_pending_key_requires_admin_approval_then_fresh_possession_proof():
    admin = local_admin()
    other = local_admin()
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        pending = prove(socket, key, public)
        assert pending["state"] == "pending"
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"] == []
    assert httpx.post(BASE + "/pairings/approve", json={"code": pending["code"]}).status_code == 401
    approved = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": pending["code"]})
    assert approved.status_code == 200
    device = approved.json()["device_id"]
    assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": pending["code"]}).status_code == 409
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]["reachability"] == "awaiting_activation"
    assert httpx.get(BASE + "/devices", headers=other).json()["devices"] == []
    wrong, _ = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, wrong, public)["state"] == "denied"
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        online = prove(socket, key, public)
        assert online == {"state": "online", "device_id": device, "heartbeat_seconds": 15, "stale_seconds": 45}
        assert httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]["reachability"] == "online"
        socket.send(json.dumps({"type": "heartbeat"}))
        assert json.loads(socket.recv()) == {"type": "heartbeat_ack"}
        socket.send(json.dumps({"type": "heartbeat"}))
        assert json.loads(socket.recv()) == {"state": "denied"}


def test_two_admins_cannot_bind_one_code_to_two_workspaces():
    admins = [local_admin(), local_admin()]
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        code = prove(socket, key, public)["code"]
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(lambda admin: httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": code}), admins))
    assert sorted(response.status_code for response in responses) == [200, 409]
    assert sorted(len(httpx.get(BASE + "/devices", headers=admin).json()["devices"]) for admin in admins) == [0, 1]


def test_recorded_possession_proof_cannot_be_replayed_on_a_new_connection():
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        challenge = json.loads(socket.recv())
        signature = key.sign(("rmm-reachability-v1\n" + challenge["nonce"]).encode(), ec.ECDSA(hashes.SHA256()))
        proof = {"public_key": public, "signature": base64.b64encode(signature).decode()}
        socket.send(json.dumps(proof))
        assert json.loads(socket.recv())["state"] == "pending"
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert json.loads(socket.recv())["nonce"] != challenge["nonce"]
        socket.send(json.dumps(proof))
        assert json.loads(socket.recv()) == {"state": "denied"}


def test_reconnecting_during_approval_never_issues_a_replacement_code():
    for _ in range(5):
        admin = local_admin()
        key, public = endpoint_key()
        with connect(BASE.replace("http", "ws") + "/agent") as socket:
            code = prove(socket, key, public)["code"]

        def reconnect():
            with connect(BASE.replace("http", "ws") + "/agent") as socket:
                return prove(socket, key, public)

        with ThreadPoolExecutor(2) as pool:
            poll = pool.submit(reconnect)
            approval = pool.submit(httpx.post, BASE + "/pairings/approve", headers=admin, json={"code": code})
            assert approval.result().status_code == 200
            status = poll.result()
        assert "code" not in status
        assert status["state"] in ("pending", "online")
        assert reconnect()["device_id"] == approval.result().json()["device_id"]


def test_approval_guesses_are_bounded_even_with_a_valid_admin():
    admin = local_admin()
    for _ in range(10):
        assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": "AAAAAAAAAAAA"}).status_code == 409
    denied = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": "AAAAAAAAAAAA"})
    assert denied.status_code == 429
    assert denied.headers["Retry-After"] == "60"
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"] == []


def test_validation_does_not_echo_secrets_or_accept_key_rebinding():
    admin = local_admin()
    secret = "dummy-secret-must-not-appear"
    invalid = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": secret})
    assert invalid.status_code == 422 and secret not in invalid.text
    oversized = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": secret * 100_000})
    assert oversized.status_code == 413 and secret not in oversized.text
    key, public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        code = prove(socket, key, public)["code"]
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public) == {"state": "pending"}
    assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": code, "public_key": "replacement"}).status_code == 422
    assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": code}).status_code == 200


def test_device_pagination_stays_inside_the_admins_workspace():
    admin = local_admin()
    other = local_admin()
    for _ in range(2):
        key, public = endpoint_key()
        with connect(BASE.replace("http", "ws") + "/agent") as socket:
            code = prove(socket, key, public)["code"]
        assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": code}).status_code == 200
    first = httpx.get(BASE + "/devices?limit=1", headers=admin).json()
    assert len(first["devices"]) == 1 and first["next_cursor"]
    second = httpx.get(BASE + "/devices", headers=admin, params={"after": first["next_cursor"], "limit": 1}).json()
    assert len(second["devices"]) == 1 and second["next_cursor"] is None
    assert first["devices"][0]["id"] != second["devices"][0]["id"]
    assert httpx.get(BASE + "/devices", headers=other, params={"after": first["next_cursor"]}).json()["devices"] == []


@pytest.mark.skipif(not os.environ.get("RMM_RATE_TEST"), reason="intentionally consumes global connection allowance")
def test_excessive_unauthenticated_connections_are_bounded():
    rejected = False
    for _ in range(121):
        try:
            with connect(BASE.replace("http", "ws") + "/agent") as socket:
                assert json.loads(socket.recv())["type"] == "challenge"
        except InvalidStatus as error:
            assert error.response.status_code == 403
            rejected = True
            break
    assert rejected
