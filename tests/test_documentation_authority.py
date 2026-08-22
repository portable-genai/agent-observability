"""Documentation authority order (G1) and the compliance mapping (G2), enforced.

RED before the 2026-08-05 documentation change: no document declared the authority order at
all, and COMPLIANCE.md pointed P-05 at `infra/terraform/iam.tf`, a file that has never
existed in this repo (the IAM grants live in `cloud_run.tf`). A mapping table whose evidence
pointers do not resolve is worse than no table, so the pointers are now checked mechanically.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# `path/like/this.ext` inside backticks. Bare words and prose are ignored on purpose.
_PATH_IN_BACKTICKS = re.compile(r"`([A-Za-z0-9_./-]+/[A-Za-z0-9_.-]+\.(?:py|tf|md|yaml|yml))`")

#: A markdown link whose target is an absolute URL. Its LABEL is often the canonical name of
#: a file that deliberately lives somewhere else, as in the shared working agreement, which is
#: labelled `.github/AGENTS.md` and linked to the organization repository that actually holds
#: it. Reading such a label as a local path reports a broken pointer at the one place the
#: pointer is explicitly not local, so these links are removed before the scan. A link with a
#: RELATIVE target is left in place, because that one does have to resolve on disk.
_ABSOLUTE_LINK = re.compile(r"\[(?:[^\]]*)\]\((?:https?:)?//[^)]*\)")


def _local_pointers(text: str) -> list[str]:
    return _PATH_IN_BACKTICKS.findall(_ABSOLUTE_LINK.sub("", text))


def test_authority_order_is_declared_and_ordered() -> None:
    agents_md = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "## Documentation authority order" in agents_md
    positions = [agents_md.index(doc) for doc in ("SPEC.md", "ARCHITECTURE.md", "COMPLIANCE.md")]
    assert positions == sorted(positions), "spec > architecture > compliance > README"
    assert "README.md" in agents_md
    assert "Staleness is a bug" in agents_md


def test_every_file_pointer_in_the_compliance_map_resolves() -> None:
    compliance = (ROOT / "COMPLIANCE.md").read_text(encoding="utf-8")

    missing = sorted({ref for ref in _local_pointers(compliance) if not (ROOT / ref).exists()})

    assert missing == [], f"COMPLIANCE.md points at files that do not exist: {missing}"


def test_authority_documents_carry_no_pointer_to_a_missing_file() -> None:
    missing: dict[str, list[str]] = {}
    for name in ("SPEC.md", "ARCHITECTURE.md", "AGENTS.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        refs = _local_pointers(text)
        gone = sorted({ref for ref in refs if not (ROOT / ref).exists()})
        if gone:
            missing[name] = gone

    assert missing == {}


def test_compliance_map_covers_every_rule_and_principle() -> None:
    compliance = (ROOT / "COMPLIANCE.md").read_text(encoding="utf-8")

    for rule in (f"**R{n}**" for n in range(1, 7)):
        assert rule in compliance
    for principle in (f"**P-{n:02d}**" for n in range(1, 13)):
        assert principle in compliance


def test_regulator_crosswalk_exists_and_names_its_owner() -> None:
    compliance = (ROOT / "COMPLIANCE.md").read_text(encoding="utf-8")

    assert "Per-regulator crosswalk (adopter-owned)" in compliance
    assert "the adopting institution owns this section" in compliance
    assert "MAS 626" in compliance
    # A template is only useful if it says what the adopter must still do.
    assert "Adopter checklist for this appendix" in compliance
