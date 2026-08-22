"""Optional Google emulator detection for the ``local`` profile (opt-in, never required).

For the stores that have an official Google emulator, the local adapters can route to it
for higher-fidelity local development WHEN the standard emulator env var is set AND the
matching client library (from the ``[gcp]`` extra) imports. Otherwise the adapters use
their SDK-free SQLite / in-process path, which is the default.

This module only *detects* the opt-in; it deliberately performs **no google-cloud import
at module top level**. The adapter that supports the emulator imports the google client
lazily, inside the method, and only on the emulator branch, so the default local path and
the offline test suite never import a google-cloud package.

There is no official emulator for Cloud Logging, so the audit WORM store always uses the
SDK-free SQLite path; the Firestore emulator is offered as an optional higher-fidelity
document store for the same append-only records.
"""

from __future__ import annotations

from hex_service_kit import read_env_setting

#: Standard emulator host env var for Firestore.
FIRESTORE_EMULATOR_ENV = "FIRESTORE_EMULATOR_HOST"


def firestore_emulator_host() -> str | None:
    """Return the Firestore emulator host if ``FIRESTORE_EMULATOR_HOST`` is set, else None."""
    return read_env_setting(FIRESTORE_EMULATOR_ENV).value or None


def firestore_client_available() -> bool:
    """Whether ``google-cloud-firestore`` is importable (the ``[gcp]`` extra is installed).

    The import is attempted lazily here (not at module top level) so that the default
    SDK-free local path never imports a google-cloud package.
    """
    try:
        import google.cloud.firestore  # noqa: F401  (lazy availability probe only)
    except Exception:  # noqa: BLE001 - any import failure means the emulator path is off
        return False
    return True


def firestore_emulator_active() -> bool:
    """True only when both the emulator env var is set AND the client lib imports."""
    return firestore_emulator_host() is not None and firestore_client_available()
