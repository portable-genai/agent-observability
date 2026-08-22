#!/usr/bin/env python3
"""Preview or apply a conservative mechanical rename of an Hrz5 fork."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OLD_PACKAGE = "observability"
_OLD_SERVICE = "agent-observability"
_OLD_ENV_PREFIX = "OBSERVABILITY_"
_OLD_DIST = "agent-observability"

_SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".terraform",
    "build",
    "dist",
}
_TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".env",
    ".example",
    ".html",
    ".ini",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".tf",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_TOOL_FILES = {
    Path("scripts/rename_fork.py"),
    Path("scripts/rename_fork_selftest.py"),
    Path("tests/test_rename_fork.py"),
}


def _iter_files(include_docs: bool) -> list[Path]:
    files = []
    for path in _ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(_ROOT)
        if relative in _TOOL_FILES or _skipped(relative):
            continue
        if path.suffix not in _TEXT_SUFFIXES:
            continue
        if not include_docs and path.suffix in {".md", ".html"}:
            continue
        files.append(path)
    return files


def _skipped(relative: Path) -> bool:
    return any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts)


def _replacements(args: argparse.Namespace) -> list[tuple[str, str]]:
    prefix = args.env_prefix.rstrip("_").upper() + "_"
    # The distribution name and the service name are the same token, so a bare replacement
    # of the first consumes every occurrence and leaves the second doing nothing: a --dist
    # that differs from --service would silently rewrite the service name too. Anchoring the
    # distribution on its pyproject declaration is what keeps the two independently meaningful.
    return [
        (f'name = "{_OLD_DIST}"', f'name = "{args.dist or args.service}"'),
        (_OLD_SERVICE, args.service),
        (_OLD_PACKAGE, args.package),
        (_OLD_ENV_PREFIX, prefix),
    ]


def _rewrite_text(text: str, replacements: list[tuple[str, str]]) -> tuple[str, int]:
    count = 0
    for old, new in replacements:
        if old == _OLD_ENV_PREFIX:
            text, changed = re.subn(rf"\b{re.escape(old)}(?=[A-Z0-9])", new, text)
        else:
            changed = text.count(old)
            text = text.replace(old, new)
        count += changed
    return text, count


def _path_renames(new_package: str) -> list[tuple[Path, Path]]:
    package_dir = _ROOT / "src" / _OLD_PACKAGE
    if not package_dir.exists():
        raise RuntimeError(f"refusing rename: source package does not exist: {package_dir}")

    renames: list[tuple[Path, Path]] = []
    for path in _ROOT.rglob("*"):
        relative = path.relative_to(_ROOT)
        if relative in _TOOL_FILES or _skipped(relative):
            continue
        new_name = path.name.replace(_OLD_PACKAGE, new_package)
        if new_name == path.name:
            continue
        destination = path.with_name(new_name)
        if destination.exists():
            raise RuntimeError(f"refusing rename: destination already exists: {destination}")
        renames.append((path, destination))
    return sorted(renames, key=lambda pair: len(pair[0].parts), reverse=True)


def _format_applied_fork() -> None:
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError("refusing apply: ruff is required to format the renamed fork")
    paths = ["src", "tests", "eval", "scripts"]
    subprocess.run(  # noqa: S603 - resolved trusted formatter executable
        [ruff, "check", "--fix", *paths],
        cwd=_ROOT,
        check=True,
    )
    subprocess.run(  # noqa: S603 - resolved trusted formatter executable
        [ruff, "format", *paths],
        cwd=_ROOT,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Rename an Hrz5 institutional fork.")
    parser.add_argument("--package", required=True, help="new snake_case Python package")
    parser.add_argument(
        "--service",
        required=True,
        help="new lowercase service/CLI resource stem",
    )
    parser.add_argument("--env-prefix", required=True, help="new environment prefix")
    parser.add_argument("--dist", default="", help="new distribution, default --service")
    parser.add_argument(
        "--include-docs", action="store_true", help="also rewrite Markdown and HTML"
    )
    parser.add_argument("--dry-run", action="store_true", help="preview without writing")
    parser.add_argument("--yes", action="store_true", help="apply without another prompt")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-z_][a-z0-9_]*", args.package):
        parser.error("--package must be a valid snake_case identifier")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", args.service):
        parser.error("--service must be a lowercase kebab-case stem")
    normalized_prefix = args.env_prefix.rstrip("_").upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", normalized_prefix):
        parser.error(
            "--env-prefix must start with a letter and contain letters, digits or underscores"
        )
    distribution = args.dist or args.service
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", distribution):
        parser.error("--dist must be a lowercase Python distribution name")

    apply_changes = args.yes and not args.dry_run
    path_renames = _path_renames(args.package)
    if apply_changes and shutil.which("ruff") is None:
        raise RuntimeError("refusing apply: ruff is required before any files are written")
    replacements = _replacements(args)
    print("Planned replacements:")
    for old, new in replacements:
        print(f"  {old!r} -> {new!r}")

    touched: list[tuple[Path, int]] = []
    for path in _iter_files(args.include_docs):
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rewritten, count = _rewrite_text(original, replacements)
        if count:
            touched.append((path, count))
            if apply_changes:
                path.write_text(rewritten, encoding="utf-8")

    print(
        f"{'Edited' if apply_changes else 'Would edit'} {len(touched)} file(s), "
        f"{sum(count for _, count in touched)} replacement(s)."
    )
    verb = "Renaming" if apply_changes else "Would rename"
    for source, destination in path_renames:
        print(f"{verb} {source} -> {destination}")
        if apply_changes:
            source.rename(destination)

    if not apply_changes:
        print("No files were written. Re-run with --yes after reviewing the preview.")
    else:
        _format_applied_fork()
        print("Rename complete. Recreate the environment and run the full adoption gate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
