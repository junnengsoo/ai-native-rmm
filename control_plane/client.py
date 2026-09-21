"""Small manual smoke client; credentials and pairing codes stay out of argv."""
import getpass
import json
import os
import sys

import httpx


def main():
    base = os.environ.get("RMM_API_URL", "http://127.0.0.1:18080").rstrip("/")
    headers = {"Authorization": "Bearer " + os.environ["RMM_TECHNICIAN_KEY"]}
    with httpx.Client(base_url=base, headers=headers, timeout=10) as client:
        if sys.argv[1:] == ["list"]:
            response = client.get("/devices")
        elif sys.argv[1:] == ["approve"]:
            response = client.post("/pairings/approve", json={"code": getpass.getpass("Code observed on Windows: ")})
        else:
            raise ValueError()
    if not response.is_success:
        print("request_denied HTTP " + str(response.status_code), file=sys.stderr)
        return 1
    print(json.dumps(response.json(), indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("request_failed", file=sys.stderr)
        sys.exit(1)
