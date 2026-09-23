import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ROOT / arguments[0]), *arguments[1:]],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_demo_shell_exposes_the_review_workflow_commands():
    result = run("demo.sh", "help")

    assert result.returncode == 0
    for command in ("start", "approve", "ai", "status", "stop", "reset"):
        assert command in result.stdout


def test_demo_shell_rejects_unknown_commands_without_side_effects():
    result = run("demo.sh", "not-a-command")

    assert result.returncode == 2
    assert "Unknown command" in result.stderr


def test_macos_azure_transfer_help_is_available_without_azure_login():
    result = run("scripts/mac/transfer-msi-to-azure.sh", "--help")

    assert result.returncode == 0
    assert "local macOS directory" in result.stdout
    assert "It does not install" in result.stdout


def test_macos_azure_install_help_is_available_without_azure_login():
    result = run("scripts/mac/install-msi-on-azure.sh", "--help")

    assert result.returncode == 0
    assert "previously transferred" in result.stdout
    assert "prints the pairing code" in result.stdout
