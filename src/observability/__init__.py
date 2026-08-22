"""Hrz5 Agent Observability, Audit & FinOps (``agent-observability``).

Catalog system **Hrz5** (group ``hrz``). A mandatory platform dependency of the Rsk1
Compliance Assistant (``compliance-advisory``): Rsk1 routes every immutable audit
record through this service's ``POST /v1/audit`` endpoint instead of writing Cloud
Logging directly. Hrz5 provides three concerns:

* **Tracing** — OpenTelemetry / Cloud Trace ingest (infra: an OTel collector, *not*
  part of this HTTP contract; see ``infra/otel/``).
* **Audit (rule R2)** — compliance-grade, immutable Write-Once-Read-Many (WORM) storage
  of already-redacted prompt/response audit events in a *locked* Cloud Logging bucket.
* **FinOps** — token cost / latency dashboards, sourced from a BigQuery export of the
  audit + trace streams (see ``infra/terraform`` and the FinOps note in the README).

The HTTP surface mirrors SPEC §6 (Hrz5) field-for-field so Rsk1's remote audit client
deserialises without translation.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__ = "0.0.1"
