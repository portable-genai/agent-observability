"""The shipped tree names this system by its CURRENT catalog id, everywhere (practice G1).

Hrz5 was once catalogued as a legacy short id, and the systems it talks to were too. A
rename that stops at ``src/`` is not a rename: the distribution metadata in
``pyproject.toml`` is what pip shows, ``config/settings.yaml`` is COPYed into the runtime
image, and the collector config stamps a ``catalog.system`` resource attribute onto every
exported span. A doc claiming "renamed throughout" is only true if something mechanical
keeps it true, so this scans the whole working tree rather than asserting substrings in
three prose files.

Exactly one file is exempt: ``docs/practices-audit.md`` is the projection of the catalog's
common base practices, whose CHECK ids (A1..G7) share spelling with the legacy system ids.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Built from parts so this file does not itself trip the scan it defines.
LEGACY_IDS = {
    "A" + "5": "Hrz5",  # this system
    "C" + "1": "Rsk1",  # the compliance assistant that writes to this system
}
_LEGACY_RE = re.compile(r"(?<![\w-])(" + "|".join(LEGACY_IDS) + r")(?![\w-])")

# The one file allowed to spell them: it quotes common-base-practices CHECK ids, not
# catalog system ids.
EXEMPT_FILES = {Path("docs/practices-audit.md")}
SKIP_DIRS = {
    ".git",
    ".venv",
    # A venv is not the shipped tree. Naming them one at a time is what broke this scan
    # once already: scripts/rename_fork_selftest.py builds ".rename-venv", CI walked into
    # its site-packages and reported legacy ids found in mypy's own source. "site-packages"
    # is the mechanical guard, so a venv under any name is skipped; the two literal names
    # below also skip the bin/ and pyvenv.cfg that sit beside it.
    ".rename-venv",
    "site-packages",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
SKIP_SUFFIXES = {".db", ".ico", ".jpg", ".jpeg", ".pdf", ".png", ".svg", ".webp"}


def _scannable_files() -> list[Path]:
    found: list[Path] = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if set(path.relative_to(REPO_ROOT).parts) & SKIP_DIRS:
            continue
        if path.relative_to(REPO_ROOT) in EXEMPT_FILES:
            continue
        found.append(path)
    return found


def test_no_legacy_catalog_ids_anywhere_in_the_tree() -> None:
    offenders: list[str] = []
    for path in _scannable_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: nothing to claim about it
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _LEGACY_RE.search(line)
            if match:
                current = LEGACY_IDS[match.group(1)]
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}:{lineno}: legacy catalog id "
                    f"(use {current}): {line.strip()[:100]}"
                )
    assert not offenders, "legacy catalog ids survive in the tree:\n" + "\n".join(offenders)


def test_the_scan_would_actually_fail_on_a_legacy_id(tmp_path: Path) -> None:
    """A guard that cannot fail guards nothing."""
    assert _LEGACY_RE.search("catalog system " + "A" + "5" + " observability")
    assert _LEGACY_RE.search("services (" + "C" + "1" + ") set as OBSERVABILITY_URL")
    assert not _LEGACY_RE.search("Hrz5 Rsk1 A55 XA5 A5x A-5")


def test_shipped_metadata_names_the_current_catalog_id() -> None:
    """The claim is positive, not just the absence of the old id."""
    metadata = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["description"].startswith("Hrz5 ")
    assert metadata["project"]["name"] == "agent-observability"

    settings = (REPO_ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")
    assert settings.splitlines()[0].startswith("# Hrz5 ")

    collector = (REPO_ROOT / "infra" / "otel" / "otel-collector-config.yaml").read_text(
        encoding="utf-8"
    )
    assert "value: Hrz5" in collector
