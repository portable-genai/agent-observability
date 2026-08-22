"""Local adapter family — SDK-free, deterministic, offline (the dev / test profile).

The ``local`` profile runs the whole Hrz5 service end to end with **no Google Cloud, no
API key, and no running emulators by default**. For the one persistence concern Hrz5 owns
(``AuditSinkPort``), the local adapter is an append-only SQLite WORM stand-in for the
locked Cloud Logging bucket: deterministic, seedable, read-back supported, pure standard
library.

An optional higher-fidelity branch routes to the official **Firestore emulator** when
``FIRESTORE_EMULATOR_HOST`` is set AND ``google-cloud-firestore`` (installed alongside the
``[gcp]`` extra) imports; the google client is imported lazily inside that branch only, so
the default local path and the offline test suite never import a google-cloud package.
"""

from __future__ import annotations
