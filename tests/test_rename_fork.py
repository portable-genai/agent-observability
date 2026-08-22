from __future__ import annotations

import importlib.util
import sys
from argparse import Namespace
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parents[1] / "scripts" / "rename_fork.py"
_SPEC = importlib.util.spec_from_file_location("rename_fork", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _args() -> Namespace:
    return Namespace(
        package="bank_audit_platform",
        service="bank-agent-audit",
        env_prefix="BANK_AUDIT",
        dist="",
    )


def test_rename_rewrites_package_service_distribution_and_env() -> None:
    rewritten, count = _MODULE._rewrite_text(
        (
            f"{_MODULE._OLD_PACKAGE} {_MODULE._OLD_ENV_PREFIX}PROFILE "
            f'{_MODULE._OLD_SERVICE} name = "{_MODULE._OLD_DIST}"'
        ),
        _MODULE._replacements(_args()),
    )

    assert count == 4
    assert rewritten == (
        'bank_audit_platform BANK_AUDIT_PROFILE bank-agent-audit name = "bank-agent-audit"'
    )


def test_a_distribution_name_differing_from_the_service_does_not_rewrite_the_service() -> None:
    """The two are the same token, so only the anchored form can tell them apart.

    Without the pyproject anchor the distribution replacement consumes every occurrence and
    the service name silently becomes the distribution name, which is the defect this proves
    is absent rather than merely believed to be.
    """
    args = Namespace(
        package="bank_audit_platform",
        service="bank-agent-audit",
        env_prefix="BANK_AUDIT",
        dist="bank-audit-dist",
    )
    rewritten, _ = _MODULE._rewrite_text(
        f'{_MODULE._OLD_SERVICE} name = "{_MODULE._OLD_DIST}"',
        _MODULE._replacements(args),
    )

    assert rewritten == 'bank-agent-audit name = "bank-audit-dist"'


def test_dry_run_does_not_mutate_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src" / _MODULE._OLD_PACKAGE
    source.mkdir(parents=True)
    config = tmp_path / "settings.py"
    original = f'PROFILE = "{_MODULE._OLD_ENV_PREFIX}PROFILE"\n'
    config.write_text(original, encoding="utf-8")

    monkeypatch.setattr(_MODULE, "_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rename_fork.py",
            "--package",
            "bank_audit_platform",
            "--service",
            "bank-agent-audit",
            "--env-prefix",
            "BANK_AUDIT",
            "--dry-run",
        ],
    )

    assert _MODULE.main() == 0
    assert source.is_dir()
    assert not (tmp_path / "src" / "bank_audit_platform").exists()
    assert config.read_text(encoding="utf-8") == original


def test_apply_preflights_destination_collision_before_any_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "src" / _MODULE._OLD_PACKAGE
    destination = tmp_path / "src" / "bank_audit_platform"
    source.mkdir(parents=True)
    destination.mkdir(parents=True)
    config = tmp_path / "settings.py"
    original = f'PROFILE = "{_MODULE._OLD_ENV_PREFIX}PROFILE"\n'
    config.write_text(original, encoding="utf-8")

    monkeypatch.setattr(_MODULE, "_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rename_fork.py",
            "--package",
            "bank_audit_platform",
            "--service",
            "bank-agent-audit",
            "--env-prefix",
            "BANK_AUDIT",
            "--yes",
        ],
    )

    with pytest.raises(RuntimeError, match="destination already exists"):
        _MODULE.main()
    assert config.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    ("extra_args", "message"),
    [
        (["--env-prefix", "1_BAD"], "--env-prefix must start with a letter"),
        (
            ["--env-prefix", "BANK_AUDIT", "--dist", "Bad Distribution"],
            "--dist must be a lowercase Python distribution name",
        ),
        (
            ["--env-prefix", "BANK_AUDIT", "--dist", "bad-"],
            "--dist must be a lowercase Python distribution name",
        ),
        (
            ["--env-prefix", "BANK_AUDIT", "--dist", "bad."],
            "--dist must be a lowercase Python distribution name",
        ),
    ],
)
def test_invalid_env_prefix_or_distribution_fails_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra_args: list[str],
    message: str,
) -> None:
    source = tmp_path / "src" / _MODULE._OLD_PACKAGE
    source.mkdir(parents=True)
    config = tmp_path / "settings.py"
    original = f'PROFILE = "{_MODULE._OLD_ENV_PREFIX}PROFILE"\n'
    config.write_text(original, encoding="utf-8")

    monkeypatch.setattr(_MODULE, "_ROOT", tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rename_fork.py",
            "--package",
            "bank_audit_platform",
            "--service",
            "bank-agent-audit",
            *extra_args,
            "--yes",
        ],
    )

    with pytest.raises(SystemExit):
        _MODULE.main()
    assert message in capsys.readouterr().err
    assert source.is_dir()
    assert config.read_text(encoding="utf-8") == original
