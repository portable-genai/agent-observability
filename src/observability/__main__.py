"""Console entrypoint: ``python -m observability`` -> the Typer CLI.

``python -m observability`` and the ``agent-observability`` script both dispatch to the
Typer app in :mod:`observability.cli.main` (commands: ``seed`` / ``record`` / ``read`` /
``serve`` / ``eval``). The CLI is import-safe: heavy imports (uvicorn, Google Cloud SDKs)
are lazy inside command bodies, so the on-prem / local profile loads with no SDK present.
"""

from __future__ import annotations


def main() -> None:
    from .cli.main import app

    app()


if __name__ == "__main__":
    main()
