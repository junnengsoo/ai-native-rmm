"""Technician recovery preserves a logical device while rotating credentials."""
import base64
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from control_plane.database import device_credentials, digest, pairings, transaction


BASE = os.environ.get("RMM_TEST_URL", "http://127.0.0.1:18080")


def local_admin(name="Recovery Trial"):
    result = subprocess.run(
        [sys.executable, "-m", "control_plane.setup", name],
        capture_output=True, text=True, check=True,
    )
    return {"Authorization": "Bearer " + result.stdout.strip()}


def operator(admin, name="recovery-operator"):
    response = httpx.post(BASE + "/callers", headers=admin, json={"name": name, "role": "operator"})
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
    socket.send(json.dumps({"public_key": public, "signature": base64.b64encode(signature).decode()}))
    return json.loads(socket.recv())


def pending(key, public):
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        return prove(socket, key, public)


def enroll(admin, device_name="Reception PC"):
    key, public = endpoint_key()
    code = pending(key, public)["code"]
    response = httpx.post(
        BASE + "/pairings/approve", headers=admin,
        json={"code": code, "device_name": device_name},
    )
    response.raise_for_status()
    device_id = response.json()["device_id"]
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public)["device_id"] == device_id
    return device_id, key, public


def test_recovery_requires_admin_and_fresh_proof_then_rotates_the_credential():
    admin = local_admin()
    other_admin = local_admin("Other Recovery Trial")
    caller = operator(admin)
    device_id, old_key, old_public = enroll(admin)
    with connect(BASE.replace("http", "ws") + "/agent") as old_socket:
        assert prove(old_socket, old_key, old_public)["device_id"] == device_id

        def endpoint_peer():
            opened = json.loads(old_socket.recv())
            old_socket.send(json.dumps({
                "type": "session_ready", "deviceId": device_id,
                "sessionId": opened["sessionId"],
            }))
            executed = json.loads(old_socket.recv())
            binding = {
                "deviceId": device_id, "sessionId": opened["sessionId"],
                "executionId": executed["executionId"],
            }
            old_socket.send(json.dumps({"type": "running", **binding}))
            old_socket.send(json.dumps({
                "type": "output", **binding, "stream": "stdout", "text": "retained\n",
            }))
            old_socket.send(json.dumps({
                "type": "result", **binding, "state": "completed",
                "invocationOutcome": "completed_normally", "exitCode": 0,
                "exitCodeSource": "normalized_invocation", "hadErrors": False,
                "durationMs": 1, "captureTruncated": False, "lastNativeExitCode": None,
            }))
            closed = json.loads(old_socket.recv())
            old_socket.send(json.dumps({
                "type": "session_closed", "deviceId": device_id,
                "sessionId": closed["sessionId"],
            }))

        with ThreadPoolExecutor(1) as pool:
            peer = pool.submit(endpoint_peer)
            opened = httpx.post(BASE + "/sessions", headers=caller, json={"device_id": device_id})
            opened.raise_for_status()
            session_id = opened.json()["session_id"]
            submitted = httpx.post(
                BASE + f"/sessions/{session_id}/executions",
                headers={**caller, "Idempotency-Key": "retained-before-recovery"},
                json={"script": "'retained'", "timeout_ms": 5000},
            )
            submitted.raise_for_status()
            execution_id = submitted.json()["execution_id"]
            completed = httpx.get(
                BASE + f"/executions/{execution_id}/wait", headers=caller,
                params={"timeout_seconds": 5},
            )
            assert completed.json()["status"] == "completed"
            httpx.post(BASE + f"/sessions/{session_id}/close", headers=caller).raise_for_status()
            peer.result(timeout=5)

        new_key, new_public = endpoint_key()
        code = pending(new_key, new_public)["code"]
        url = BASE + f"/devices/{device_id}/recover"

        assert httpx.post(url, json={"code": code}).status_code == 401
        assert httpx.post(url, headers=caller, json={"code": code}).status_code == 403
        assert httpx.post(url, headers=other_admin, json={"code": code}).status_code == 404

        approved = httpx.post(url, headers=admin, json={"code": code})
        assert approved.status_code == 200
        assert approved.json() == {
            "device_id": device_id,
            "device_name": "Reception PC",
            "state": "awaiting_activation",
        }
        assert httpx.post(url, headers=admin, json={"code": code}).json() == approved.json()

        with transaction() as connection:
            credentials = connection.execute(device_credentials.select().where(
                device_credentials.c.device_id == device_id
            )).mappings().all()
        by_public_key = {credential["public_key"]: credential for credential in credentials}
        assert len(credentials) == 2
        assert by_public_key[old_public]["replaces_credential_id"] is None
        assert (by_public_key[new_public]["replaces_credential_id"]
                == by_public_key[old_public]["id"])

        listed = httpx.get(BASE + "/devices", headers=admin).json()["devices"]
        assert listed[0]["id"] == device_id and listed[0]["device_name"] == "Reception PC"

        with connect(BASE.replace("http", "ws") + "/agent") as socket:
            activated = prove(socket, new_key, new_public)
            assert activated["state"] == "online" and activated["device_id"] == device_id

        try:
            old_socket.recv(timeout=2)
            raise AssertionError("replaced credential's live channel remained connected")
        except ConnectionClosed:
            pass

    retained = httpx.get(BASE + f"/sessions/{session_id}", headers=caller)
    assert retained.status_code == 200 and retained.json()["device_id"] == device_id
    output = httpx.get(BASE + f"/executions/{execution_id}/output/stdout", headers=caller)
    assert output.status_code == 200 and output.json()["text"] == "retained\n"

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, old_key, old_public) == {"state": "denied"}

    newest_key, newest_public = endpoint_key()
    newest_code = pending(newest_key, newest_public)["code"]
    response = httpx.post(
        BASE + f"/devices/{device_id}/recover",
        headers=admin,
        json={"code": newest_code},
    )
    assert response.status_code == 200
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, newest_key, newest_public)["device_id"] == device_id

    with transaction() as connection:
        credentials = connection.execute(device_credentials.select().where(
            device_credentials.c.device_id == device_id
        )).mappings().all()
    by_public_key = {credential["public_key"]: credential for credential in credentials}
    assert len(credentials) == 3
    assert by_public_key[old_public]["replaces_credential_id"] is None
    assert (by_public_key[new_public]["replaces_credential_id"]
            == by_public_key[old_public]["id"])
    assert (by_public_key[newest_public]["replaces_credential_id"]
            == by_public_key[new_public]["id"])

    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, new_key, new_public) == {"state": "denied"}


def test_recovery_refuses_revoked_devices_and_competing_replacements():
    admin = local_admin()
    device_id, _, _ = enroll(admin, "Lab PC")
    first_key, first_public = endpoint_key()
    second_key, second_public = endpoint_key()
    first_code = pending(first_key, first_public)["code"]
    second_code = pending(second_key, second_public)["code"]
    url = BASE + f"/devices/{device_id}/recover"

    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(
            lambda code: httpx.post(url, headers=admin, json={"code": code}),
            (first_code, second_code),
        ))
    assert sorted(response.status_code for response in responses) == [200, 409]
    winner_key, winner_public = (
        (first_key, first_public) if responses[0].status_code == 200
        else (second_key, second_public)
    )

    def activate_winner():
        with connect(BASE.replace("http", "ws") + "/agent") as socket:
            return prove(socket, winner_key, winner_public)

    with ThreadPoolExecutor(2) as pool:
        activations = list(pool.map(lambda _: activate_winner(), range(2)))
    assert all(result["state"] == "online" and result["device_id"] == device_id
               for result in activations)

    # A different device proves the permanent revocation boundary independently.
    revoked_id, _, _ = enroll(admin, "Revoked PC")
    assert httpx.post(BASE + f"/devices/{revoked_id}/revoke", headers=admin).status_code == 200
    replacement_key, replacement_public = endpoint_key()
    replacement_code = pending(replacement_key, replacement_public)["code"]
    refused = httpx.post(
        BASE + f"/devices/{revoked_id}/recover", headers=admin,
        json={"code": replacement_code},
    )
    assert refused.status_code == 409
    assert refused.json() == {"detail": "device_revoked"}


def test_device_names_are_workspace_unique_and_admin_rename_is_scoped():
    admin = local_admin()
    other_admin = local_admin("Rename Other")
    caller = operator(admin, "rename-operator")
    device_id, _, _ = enroll(admin, "Front Desk")

    renamed = httpx.patch(
        BASE + f"/devices/{device_id}", headers=admin,
        json={"device_name": "Front Desk Main"},
    )
    assert renamed.status_code == 200
    assert renamed.json() == {"device_id": device_id, "device_name": "Front Desk Main"}
    assert httpx.patch(
        BASE + f"/devices/{device_id}", headers=caller,
        json={"device_name": "Forbidden"},
    ).status_code == 403
    assert httpx.patch(
        BASE + f"/devices/{device_id}", headers=other_admin,
        json={"device_name": "Hidden"},
    ).status_code == 404

    key, public = endpoint_key()
    code = pending(key, public)["code"]
    conflict = httpx.post(
        BASE + "/pairings/approve", headers=admin,
        json={"code": code, "device_name": "Front Desk Main"},
    )
    assert conflict.status_code == 409
    assert conflict.json() == {"detail": "device_name_conflict"}


def test_recovery_errors_do_not_echo_pairing_material():
    admin = local_admin()
    device_id, _, _ = enroll(admin, "Secret Safe PC")
    secret = "not-a-valid-code-and-must-not-appear"
    invalid = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin, json={"code": secret},
    )
    assert invalid.status_code == 422 and secret not in invalid.text

    key, public = endpoint_key()
    code = pending(key, public)["code"]
    approved = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin, json={"code": code},
    )
    assert approved.status_code == 200
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, key, public)["device_id"] == device_id
    consumed = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin, json={"code": code},
    )
    assert consumed.status_code == 409 and code not in consumed.text


def test_expired_code_and_activation_never_invalidate_the_current_credential():
    admin = local_admin()
    device_id, old_key, old_public = enroll(admin, "Expiry PC")

    expired_key, expired_public = endpoint_key()
    expired_code = pending(expired_key, expired_public)["code"]
    # Database time is authoritative. Move only the test fixture's deadline so
    # the public API can exercise expiry without a real ten-minute wait.
    with transaction() as connection:
        connection.execute(pairings.update().where(
            pairings.c.code_hash == digest(expired_code)
        ).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    refused = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin,
        json={"code": expired_code},
    )
    assert refused.status_code == 409 and expired_code not in refused.text

    replacement_key, replacement_public = endpoint_key()
    replacement_code = pending(replacement_key, replacement_public)["code"]
    approved = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin,
        json={"code": replacement_code},
    )
    assert approved.status_code == 200
    with transaction() as connection:
        connection.execute(device_credentials.update().where(
            device_credentials.c.public_key == replacement_public
        ).values(activate_before=datetime.now(timezone.utc) - timedelta(seconds=1)))
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, replacement_key, replacement_public) == {"state": "denied"}
    with connect(BASE.replace("http", "ws") + "/agent") as socket:
        assert prove(socket, old_key, old_public)["device_id"] == device_id

    # Expired replacement state is cleared deterministically for a later attempt.
    later_key, later_public = endpoint_key()
    later_code = pending(later_key, later_public)["code"]
    later = httpx.post(
        BASE + f"/devices/{device_id}/recover", headers=admin,
        json={"code": later_code},
    )
    assert later.status_code == 200 and later.json()["device_id"] == device_id
