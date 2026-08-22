"""The core imports only the standard library, its own package and the workspace kits.

The core is the code a client owns outright after an extraction: the decision records, the
serialization of them and the port contracts. A cloud or model SDK import there is lock-in
wearing a green gate. The rule is an allowlist rather than an SDK blocklist, because a
blocklist rots the day a vendor renames a distribution.

THIS REPOSITORY HAS NO ``domain/`` PACKAGE. Hrz5 is a persistence-and-audit service, so its
core sits flat beside the wiring: ``models.py`` (the audit event, citation and decision
records), ``serialization.py`` (their stdlib JSON form), ``errors.py`` (the ingestion errors)
and the ``ports/`` package (the Protocols and the identity scheme declarations).
:data:`CORE_LAYERS` therefore names modules as well as directories, and the scan below accepts
either. Everything else under ``src/observability`` is deliberately outside that boundary and
free to depend on its framework: ``config.py`` and ``schemas.py`` are the YAML / pydantic edge,
``container.py`` is the wiring, and ``api/``, ``cli/`` and ``adapters/`` are adapters by
definition.

Twin of the core-purity section of the fleet-wide portfolio gate,
which repeats this scan across every repository in the workspace. This copy travels with the
repository when it is extracted and handed over, which is exactly when the workspace scan can
no longer see it.

The dynamic blocked-import probe (``tests/_sdk_free_probe.py``) proves the SDK-free profiles
construct with the SDK unimportable; this static scan additionally catches a lazy import
inside a function body on a call path that profile construction never exercises.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

#: The workspace kits a core may import: stdlib-pure, versioned, owned in this catalog.
ALLOWED_KITS = frozenset(
    {
        "agent_eval_kit",
        "consent_preference_kit",
        "hex_service_kit",
        "review_kit",
        "obligation_register",
        "pii_kit",
        "speech_lexicon_kit",
    }
)

#: The core of this repository, named module by module because it is flat. A directory entry
#: is scanned recursively; a ``.py`` entry is scanned on its own.
CORE_LAYERS = ("errors.py", "models.py", "serialization.py", "ports")

_STDLIB = frozenset(sys.stdlib_module_names)


def _core_trees() -> list[tuple[str, Path]]:
    trees: list[tuple[str, Path]] = []
    for package in sorted(p for p in SRC.iterdir() if (p / "__init__.py").is_file()):
        for layer in CORE_LAYERS:
            target = package / layer
            if target.is_dir() or target.is_file():
                trees.append((package.name, target))
    return trees


def _python_files(tree: Path) -> list[Path]:
    """Every module a core entry covers: a package recursively, a module on its own."""
    return sorted(tree.rglob("*.py")) if tree.is_dir() else [tree]


def _violations(
    trees: list[tuple[str, Path]], allowed_kits: frozenset[str]
) -> tuple[int, list[str]]:
    """(files scanned, violation lines). Factored so the control test can aim it at a bad tree."""
    scanned = 0
    found: list[str] = []
    for own_pkg, tree in trees:
        for source in _python_files(tree):
            scanned += 1
            syntax = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(syntax):
                if isinstance(node, ast.Import):
                    imported = [(alias.name, node.lineno) for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    imported = [(node.module or "", node.lineno)]
                else:
                    continue
                for dotted, lineno in imported:
                    top = dotted.split(".")[0]
                    if not top or top in _STDLIB or top == own_pkg or top in allowed_kits:
                        continue
                    location = (
                        source.relative_to(REPO_ROOT)
                        if source.is_relative_to(REPO_ROOT)
                        else source
                    )
                    found.append(f"{location}:{lineno}: imports {top}")
    return scanned, found


def test_the_core_imports_only_what_it_owns() -> None:
    trees = _core_trees()
    assert trees, "no core trees found under src/; a scan of nothing proves nothing"
    scanned, found = _violations(trees, ALLOWED_KITS)
    assert scanned > 0, "core trees exist but hold no python modules; the scan saw nothing"
    assert not found, "the core imports code it does not own:\n" + "\n".join(found)


def test_every_named_core_layer_exists() -> None:
    """A renamed core module must fail loudly, not silently shrink the scan to nothing."""
    packages = [p for p in SRC.iterdir() if (p / "__init__.py").is_file()]
    assert len(packages) == 1, f"expected one package under src/, found {sorted(packages)}"
    missing = [layer for layer in CORE_LAYERS if not (packages[0] / layer).exists()]
    assert not missing, f"CORE_LAYERS names {missing}, which no longer exist in {packages[0]}"


def test_the_scan_can_see_a_violation(tmp_path: Path) -> None:
    """The positive control: a scanner that cannot go red is decoration, not a gate."""
    bad = tmp_path / "domain"
    bad.mkdir()
    (bad / "impure.py").write_text("import boto3\n", encoding="utf-8")
    scanned, found = _violations([("synthetic_pkg", bad)], ALLOWED_KITS)
    assert scanned == 1
    assert found and "imports boto3" in found[0]


def test_the_scan_can_see_a_violation_in_a_flat_core_module(tmp_path: Path) -> None:
    """The control for the shape THIS repo actually has: a single module, not a package."""
    module = tmp_path / "models.py"
    module.write_text("from google.cloud import logging_v2\n", encoding="utf-8")
    scanned, found = _violations([("synthetic_pkg", module)], ALLOWED_KITS)
    assert scanned == 1
    assert found and "imports google" in found[0]


def test_the_scan_treats_relative_and_own_imports_as_owned(tmp_path: Path) -> None:
    """``from . import x`` and imports of the owning package must not false-positive."""
    tree = tmp_path / "domain"
    tree.mkdir()
    (tree / "clean.py").write_text(
        "from . import sibling\nimport json\nfrom synthetic_pkg.ports import thing\n",
        encoding="utf-8",
    )
    scanned, found = _violations([("synthetic_pkg", tree)], ALLOWED_KITS)
    assert scanned == 1
    assert not found
