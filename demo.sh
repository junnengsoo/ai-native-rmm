#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
command=${1:-help}
[[ $# -eq 0 ]] || shift

case "$command" in
  start)
    exec "$root/scripts/mac/start-demo.sh" "$@"
    ;;
  approve)
    exec "$root/scripts/mac/approve-device.sh" "$@"
    ;;
  ai)
    exec "$root/scripts/mac/run-ai-driver.sh" "$@"
    ;;
  status)
    exec "$root/scripts/mac/status-demo.sh" "$@"
    ;;
  stop)
    exec "$root/scripts/mac/stop-demo.sh" "$@"
    ;;
  reset)
    exec "$root/scripts/mac/reset-demo.sh" "$@"
    ;;
  help|-h|--help)
    cat <<'EOF'
AI-Native RMM reviewer demo

Usage: ./demo.sh COMMAND [OPTIONS]

Commands:
  start      Create or resume the control plane; starts a tunnel by default
  approve    Prompt for the pairing code and generate caller configuration
  ai         Run the interactive AI diagnostic console
  status     Show control-plane and endpoint status without changing state
  stop       Stop services while preserving state and credentials
  reset      Delete only this demo's state and start a fresh environment

Examples:
  ./demo.sh start
  ./demo.sh start --local-only
  ./demo.sh start --public-url https://rmm.example.com
  ./demo.sh approve
  ./demo.sh ai
  ./demo.sh ai --once "Why can this machine not reach the file server?"
EOF
    ;;
  *)
    printf 'Unknown command: %s\nRun ./demo.sh help for usage.\n' "$command" >&2
    exit 2
    ;;
esac
