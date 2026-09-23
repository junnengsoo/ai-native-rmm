"""Create disposable demo callers. Secrets are delivered once on stdout."""
import json
import secrets
import sys

from ..database import create_caller, create_workspace_with_admin, digest, initialize


def main() -> None:
    initialize()
    admin_key = "rmm_" + secrets.token_urlsafe(32)
    operator_key = "rmm_" + secrets.token_urlsafe(32)
    workspace_id, admin_id = create_workspace_with_admin("Reviewer Demo", digest(admin_key))
    create_caller(workspace_id, admin_id, "demo-operator", "operator", digest(operator_key))
    print(json.dumps({"admin_key": admin_key, "operator_api_key": operator_key}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("demo_setup_failed", file=sys.stderr)
        raise SystemExit(1)
