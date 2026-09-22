"""Routine peer disconnects must not become noisy server failures."""
import socket
import os
import subprocess
import sys
import time
from contextlib import contextmanager

import httpx
from websockets.sync.client import connect


@contextmanager
def running_server(*, env=None, lifespan="on"):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "control_plane.app:app", "--host", "127.0.0.1",
         "--port", str(port), "--no-access-log", "--log-level", "warning", "--ws-max-size", "2048",
         "--lifespan", lifespan],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    try:
        for _ in range(50):
            try:
                assert httpx.get(f"http://127.0.0.1:{port}/docs").status_code == 200
                break
            except httpx.ConnectError:
                time.sleep(0.1)
        else:
            raise AssertionError("test service did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.terminate()
        output, _ = server.communicate(timeout=10)
    assert "Traceback" not in output
    assert "ERROR" not in output


def test_peer_disconnect_does_not_emit_a_server_traceback():
    with running_server() as base:
        for _ in range(3):
            with connect(base.replace("http", "ws") + "/agent") as peer:
                peer.recv()
                # Real transport loss, without a WebSocket closing handshake.
                peer.socket.shutdown(socket.SHUT_RDWR)
                peer.socket.close()
        time.sleep(0.2)


def test_unexpected_database_failure_returns_sanitized_503():
    # Exercise a real driver/configuration failure through HTTP, without mocking
    # application collaborators. Skip startup so the fault occurs during a request.
    secret = "dummy-connection-secret-must-not-appear"
    env = dict(os.environ, RMM_DATABASE_URL=secret)
    with running_server(env=env, lifespan="off") as base:
        response = httpx.get(base + "/devices", headers={"Authorization": "Bearer dummy-admin-secret"})
        assert response.status_code == 503
        assert response.json() == {"detail": "temporarily_unavailable"}
        assert secret not in response.text
        # Body rejection remains independent of database availability.
        oversized = httpx.post(base + "/pairings/approve", content="x" * 2049)
        assert oversized.status_code == 413
