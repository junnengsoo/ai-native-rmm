"""Approve one console-supplied pairing code and wait for online evidence."""
import json
import os
import sys
import time

import httpx


def main() -> None:
    code = sys.stdin.readline().strip()
    key = os.environ["RMM_ADMIN_KEY"]
    base_url = os.environ.get("RMM_API_URL", "http://127.0.0.1:8000").rstrip("/")
    if not code:
        raise ValueError("pairing_code_required")
    headers = {"Authorization": "Bearer " + key}
    with httpx.Client(base_url=base_url, headers=headers, timeout=10) as client:
        response = client.post("/pairings/approve", json={"code": code})
        response.raise_for_status()
        device_id = response.json()["device_id"]
        deadline = time.monotonic() + 45
        state = "approved"
        while time.monotonic() < deadline:
            devices = client.get("/devices").raise_for_status().json()["devices"]
            match = next((item for item in devices if item["id"] == device_id), None)
            if match is not None:
                state = match["reachability"]
                if state == "online":
                    break
            time.sleep(1)
    print(json.dumps({"device_id": device_id, "reachability": state}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("device_approval_failed", file=sys.stderr)
        raise SystemExit(1)
