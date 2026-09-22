"""Local administrative operation. stdout is the one-time credential delivery."""
import secrets
import sys
from .database import create_workspace_with_admin, digest, initialize


def main():
    if len(sys.argv) != 2 or not 1 <= len(sys.argv[1]) <= 100:
        raise ValueError("workspace_name_required")
    initialize()
    credential = "rmm_" + secrets.token_urlsafe(32)
    create_workspace_with_admin(sys.argv[1], digest(credential))
    print(credential)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("local_setup_failed", file=sys.stderr)
        sys.exit(1)
