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
