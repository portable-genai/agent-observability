# agent-observability

The shared working agreement is [`.github/AGENTS.md`](https://github.com/portable-genai/.github/blob/main/AGENTS.md).
It carries the architecture rules, the gate contract, the fleet invariants, the
falsification discipline, versions and house style, and it holds in every repository
here. Read it first. This file carries only what is specific to this one.

## Documentation authority order

When two documents disagree, the higher one wins and the lower one is the bug:

1. **[`SPEC.md`](SPEC.md)**: locked decisions. The HTTP contract, the profile matrix, the
   field-for-field wire shape. Changing behaviour means changing SPEC first.
2. **[`ARCHITECTURE.md`](ARCHITECTURE.md)**: ports, adapters, sequences, deployment posture.
   How the decisions in SPEC are realised.
3. **[`COMPLIANCE.md`](COMPLIANCE.md)**: the principle-to-control map (R1..R6, P-01..P-12)
   with file pointers, plus the adopter-owned regulator crosswalk.
4. **[`README.md`](README.md)** and everything under [`docs/`](docs/): orientation,
   adoption, runbook, FAQ. Never the source of a contract.

Two rules keep the order true:

* **Staleness is a bug, not documentation debt.** A shipped feature described as
  forthcoming, or a file reference that no longer resolves, is a defect to fix in the same
  change that caused it.
* **One fact, one home.** Higher layers link down; they do not restate. If a number
  (retention days, a threshold, a region) appears twice, one of the two is wrong already.

[`docs/practices-audit.md`](docs/practices-audit.md) is not part of this order: it is the
repo's projection of the catalog's common base practices, reconciled to the
cross-repo audit summary in the catalog repository, and it must never claim more than the
tests and configuration in the tree actually prove.

## What this is

Catalog system **Hrz5**: the platform's observability, WORM audit and FinOps system of
record. Package `observability`, env prefix `OBSERVABILITY`, CLI `agent-observability`.

## What each document owns

1. **[`SPEC.md`](SPEC.md)**: locked decisions. The HTTP contract, the profile matrix, the
   field-for-field wire shape. Changing behaviour means changing SPEC first.
2. **[`ARCHITECTURE.md`](ARCHITECTURE.md)**: ports, adapters, sequences, deployment posture.
   How the decisions in SPEC are realised.
3. **[`COMPLIANCE.md`](COMPLIANCE.md)**: the principle-to-control map (R1..R6, P-01..P-12)
   with file pointers, plus the adopter-owned regulator crosswalk.
4. **[`README.md`](README.md)** and everything under [`docs/`](docs/): orientation,
   adoption, runbook, FAQ. Never the source of a contract.

[`docs/practices-audit.md`](docs/practices-audit.md) is not part of that order: it is the
repo's projection of the catalog's common base practices, reconciled to the
cross-repo audit summary in the catalog repository, and it must never claim more than the
tests and configuration in the tree actually prove.

## The gate

The gate runs on the `local` profile:

```
ruff check . && ruff format --check . && mypy src && pytest -m 'not integration' \
  && python eval/run_eval.py
```

`make check` adds the demo self-test and the bounded portability proof, which CI also runs.

## House rules specific to this repo

* Events arrive **already redacted**. Hrz5 never redacts (that is Hrz1) and must never gain
  a raw-PII column.
* **The loopback exposure guard is derived from the CALLER-IDENTITY BINDING, and from nothing
  else.** A caller is authenticated when the scheme the active binding names resolves it from
  something verified server side against an issuer, and the scheme DECLARES that
  (`src/observability/ports/identity.py`: `VERIFIED` / `PRESHARED` / `UNIMPLEMENTED`,
  defaulting to pre-shared when silent; bound per profile in
  `src/observability/api/security.py`, which derives `SECURE_PROFILES` from the same
  declarations). `OBSERVABILITY_S2S_TOKEN` may never enter that decision: while it did, SETTING
  it switched the guard off and a LAN peer holding nothing read `/healthz` and the whole
  `/v1/capabilities` manifest. `tests/test_caller_auth_posture.py` walks the guard's argument
  through the constants and functions it names and fails the build if a credential reappears at
  any depth; `scripts/prove-exposure-matrix.sh` drives the whole matrix over a real socket.
* **A gate test must never PIN a defect.**
  `test_setting_a_token_lifts_the_bound_because_callers_are_then_authenticated`
  asserted that fail-open in green ink, so fixing the guard broke the
  build. When a fail-open is removed, find the test that was asserting it and rewrite it into the
  regression guard for the fix.
* **A placeholder on a serving path refuses with a status and a reason.** A bare
  `NotImplementedError` reaches a caller as a bodyless 500. Raise
  `ports.identity.PortabilityPlaceholderError` (501 plus a reason, and still a
  `NotImplementedError` so the exit family's uniform refusal holds).
* The audit trail is append-only in the store, not by convention: SQLite triggers plus the
  hash chain in `src/observability/adapters/local/audit.py`. Any change there must keep
  `tests/test_audit_chain.py` honest, including the test that asserts what is NOT detected.
* Commons first. Cross-cutting layers come from the shared packages pinned in
  `pyproject.toml` (`hex-service-kit`), never copied from a sibling repo.
