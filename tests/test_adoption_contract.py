from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_primary_adoption_navigation_targets_exist() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    targets = [
        "docs/ADOPTING.md",
        "docs/faq/README.md",
        "DEMO.md",
        "docs/runbook.md",
        "docs/onprem-migration.md",
    ]

    for target in targets:
        assert f"]({target})" in readme
        assert (ROOT / target).is_file()


def test_ci_gates_demo_and_portability_proofs() -> None:
    workflow = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")

    assert "make demo-selftest" in workflow
    assert "make portability-demo" in workflow
    assert "make rename-selftest" in workflow
