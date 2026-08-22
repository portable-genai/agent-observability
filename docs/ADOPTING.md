# Adopting Hrz5

Hrz5 is a reference audit, observability and FinOps service. An institution can consume
it unchanged, fork it, or implement its audit port behind an existing evidence platform.
Prefer configuration and adapter replacement over changing the event or wire contracts.

## Choose the adoption mode

| Mode | Use when | Institution-owned changes |
|---|---|---|
| Consume Hrz5 | The REST event contract and managed GCP posture fit | S2S identity, project/region inputs, retention approval, alerting and Terraform state |
| Fork Hrz5 | Naming, release cadence or evidence ownership must be independent | Rename, adapters, deployment, retention policy and regulator crosswalk |
| Implement the port | An existing WORM platform must remain authoritative | New `AuditSinkPort` adapter, exact profile binding and contract/evidence tests |

Hrz1 owns redaction before records arrive. Hrz3 owns workload and entitlement registry,
Hrz4 owns quality promotion, Hrz7 owns human decisions, and Hrz5 preserves their durable
execution evidence. Do not move those responsibilities into this repository.

## Stable and institution-owned surfaces

Keep these portable contracts stable:

- `src/observability/models.py`, `ports/` and `serialization.py`;
- `src/observability/schemas.py` and `api/` for the wire boundary;
- `tests/test_adapter_parity.py` and `eval/` for profile and evidence integrity;
- `scripts/portability_demo.py` for the bounded exit proof.

Institution-owned surfaces are `config/settings.yaml`, adapter implementations,
`infra/terraform/`, S2S registration, retention/legal approval, notification routing and
the regulator-specific control crosswalk. Local SQLite is a bounded demo buffer, not a
replacement for the managed locked WORM store.

## Preview and apply a rename

The tool previews by default and refuses a package-directory collision.

```bash
python scripts/rename_fork.py \
  --package bank_audit_platform \
  --service bank-agent-audit \
  --env-prefix BANK_AUDIT \
  --include-docs --dry-run

python scripts/rename_fork.py \
  --package bank_audit_platform \
  --service bank-agent-audit \
  --env-prefix BANK_AUDIT \
  --include-docs --yes
```

The apply renames matching source/package filenames as well as contents and runs Ruff
formatting before it returns. Recreate the virtual environment because editable-install
metadata points to the old package, then run `make check` and
`terraform -chdir=infra/terraform validate`. CI runs `make rename-selftest`, which applies
the rename in a clean copy, installs committed locks into a fresh environment and runs its
full gate. The rename utilities and their tests retain upstream identifiers so the
one-time tool remains testable.

## Keep a fork current

Add this repository as an `upstream` remote and integrate one released version at a time.
Resolve contract files before institution-owned adapters, and never
overwrite local Terraform state, retention approval, S2S identities or regulator mappings.
Run the full offline gate plus the institution's deployment and restoration evidence.

## Exit test

Before claiming an on-premises migration, replace the fail-closed adapter with an immutable
store, prove retention and tamper evidence, export and restore the complete audit trail,
and rerun `make portability-demo`. The included proof establishes the profile seam, one
SQLite reopen and one open JSON event reload; it does not prove a complete WORM migration.
