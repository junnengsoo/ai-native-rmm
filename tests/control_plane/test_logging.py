"""Routine peer disconnects must not become noisy server failures."""
import socket
import subprocess
import sys
import time

import httpx
from websockets.sync.client import connect


def test_peer_disconnect_does_not_emit_a_server_traceback():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "control_plane.app:app", "--host", "127.0.0.1",
         "--port", str(port), "--no-access-log", "--log-level", "warning", "--ws-max-size", "2048"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
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
        for _ in range(3):
            with connect(f"ws://127.0.0.1:{port}/agent") as peer:
                peer.recv()
                # Real transport loss, without a WebSocket closing handshake.
                peer.socket.shutdown(socket.SHUT_RDWR)
                peer.socket.close()
        time.sleep(0.2)
    finally:
        server.terminate()
        output, _ = server.communicate(timeout=10)
    assert "Traceback" not in output
    assert "ERROR" not in output
