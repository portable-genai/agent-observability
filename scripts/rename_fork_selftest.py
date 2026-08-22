#!/usr/bin/env python3
"""Apply the Hrz5 rename in an isolated copy and run a fresh locked full gate."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SKIP = {
    ".git",
    ".venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "__pycache__",
    "build",
    "dist",
}


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in _SKIP or name.endswith(".egg-info")}


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)  # noqa: S603


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="hrz5-rename-selftest-") as tmp:
        fork = Path(tmp) / "fork"
        shutil.copytree(_ROOT, fork, ignore=_ignore)

        _run(
            [
                sys.executable,
                "scripts/rename_fork.py",
                "--package",
                "bank_audit_platform",
                "--service",
                "bank-agent-audit",
                "--env-prefix",
                "BANK_AUDIT",
                "--dist",
                "bank-agent-audit",
                "--include-docs",
                "--yes",
            ],
            cwd=fork,
        )
        renamed_demo = fork / "scripts" / "bank_audit_platform_demo.py"
        if not renamed_demo.is_file() or (fork / "scripts" / "observability_demo.py").exists():
            raise RuntimeError("applied rename did not move the presenter demo filename")

        venv = fork / ".rename-venv"
        _run([sys.executable, "-m", "venv", str(venv)], cwd=fork)
        python = venv / "bin" / "python"
        pip = venv / "bin" / "pip"
        _run([str(pip), "install", "-r", "requirements-dev.lock"], cwd=fork)
        _run([str(pip), "install", "--no-deps", "-e", "."], cwd=fork)

        env = os.environ.copy()
        env["PATH"] = f"{venv / 'bin'}{os.pathsep}{env.get('PATH', '')}"
        _run(["make", "check", f"PY={python}"], cwd=fork, env=env)

    print("PASS rename self-test: clean copy, fresh locked install and full gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
