# Portability FAQ

## What does the executable proof establish?

`make portability-demo` proves the explicit profile map, a local SQLite reopen, one open
JSON event export/reload, SDK-free GCP adapter construction, fail-closed on-premises
behavior and rejection of an unknown profile.

## What does it not establish?

It does not prove live GCP, local tamper evidence, a completed on-premises WORM store,
managed-bucket migration, identity portability or portable trace/FinOps infrastructure.

## Who owns adjacent portability concerns?

Hrz3 owns identity/entitlement portability, Hrz4 owns quality evidence, Hrz7 owns portable
human-review state, and each producer owns its own business data migration.
