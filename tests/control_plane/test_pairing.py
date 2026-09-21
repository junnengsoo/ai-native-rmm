"""Public HTTP/WSS behavior; real PostgreSQL, no private database assertions."""
import os
import subprocess
import sys
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from websockets.sync.client import connect
import pytest

BASE = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")


def local_technician():
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


def test_pending_key_requires_technician_approval_then_fresh_possession_proof():
    admin = local_technician()
    other = local_technician()
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
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]["reachability"] == "approved"
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


def test_two_technicians_cannot_bind_one_code_to_two_workspaces():
    admins = [local_technician(), local_technician()]
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


def test_approval_guesses_are_bounded_even_with_a_valid_technician():
    admin = local_technician()
    for _ in range(10):
        assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": "AAAAAAAAAAAA"}).status_code == 409
    denied = httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": "AAAAAAAAAAAA"})
    assert denied.status_code == 429
    assert denied.headers["Retry-After"] == "60"
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"] == []


@pytest.mark.skipif(not os.environ.get("RMM_EXPIRY_TEST"), reason="ten-minute real-time expiry gate")
def test_expired_code_and_approved_but_unproven_key_cannot_activate():
    admin = local_technician()
    pending_key, pending_public = endpoint_key()
    approved_key, approved_public = endpoint_key()
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        pending = prove(socket, pending_key, pending_public)
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        approved = prove(socket, approved_key, approved_public)
    assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": approved["code"]}).status_code == 200
    deadline = time.monotonic() + 601
    while time.monotonic() < deadline:
        time.sleep(1)
    assert httpx.post(BASE + "/pairings/approve", headers=admin, json={"code": pending["code"]}).status_code == 409
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, approved_key, approved_public)["state"] == "denied"
    assert httpx.get(BASE + "/devices", headers=admin).json()["devices"][0]["reachability"] == "approval_expired"
