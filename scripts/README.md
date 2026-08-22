# Demo scripts: Hrz5 Agent Observability, Audit & FinOps

Hrz5 is a **platform service** (REST API + CLI, no web UI), so the demo is terminal /
curl-based, not browser-based. Everything here is SDK-free and runs against the in-process
`local` stack (the bounded append-only-by-API SQLite demo buffer): **no Google Cloud, no API key, no
emulators**. Run from the repo root with the package and test fixtures on the path:

```bash
export PYTHONPATH=src:tests
```

| Script | What it does |
|--------|--------------|
| `observability_demo.py` | A presenter-controlled, assertion-backed walkthrough that drives the real `local` profile, writes a JSON evidence artifact and fails if any step drifts. |
| `portability_demo.py` | A bounded proof of the adapter map, SQLite reopen, open JSON event reload, lazy managed construction, fail-closed exit and unknown-profile rejection. |
| `rename_fork.py` | A dry-run-first mechanical rename for an institutional fork. |
| `prove-exposure-matrix.sh` | The loopback exposure guard's standing proof, over a REAL socket: `OBSERVABILITY_PROFILE` (unset, empty, mis-capitalised, `local`, `onprem`, `gcp`) x `OBSERVABILITY_S2S_TOKEN` (unset, empty, set) x bearer (absent, present) against uvicorn bound to `0.0.0.0`, probed from this machine's own LAN address, requiring every cell to refuse or to refuse to boot. Not a demo: run it with `bash scripts/prove-exposure-matrix.sh`. `tests/test_serving_path_exposure.py` covers the same ground with a TestClient in the offline gate; only a bound server proves what a stranger actually gets. |

## Guided, presenter-controlled walkthrough

```bash
PYTHONPATH=src:tests python scripts/observability_demo.py
# or, from the Makefile:
make demo
```

The walkthrough is **paced by you**: it prints what the next step will do and waits for you
to press **Enter**, then runs the real CLI/adapter call and prints the artifact. The six
steps are: seed -> regulator pull (read-back) -> append + prove WORM -> scoped pull (filter
by actor) -> FinOps rollup -> `onprem` fail-fast.

There is **no browser** (Hrz5 has no UI), so unlike the cdd-sow template there is no
Playwright step. To self-run with no prompts (CI / recording), set `DEMO_AUTO=1`:

```bash
DEMO_AUTO=1 DEMO_OUT=/tmp/hrz5-demo.json \
  PYTHONPATH=src:tests python scripts/observability_demo.py
# or
make demo-selftest
```

The script seeds an ephemeral file-backed buffer under a temp dir and prints its path
at the end. It also writes an assertion-backed JSON evidence artifact:

```bash
OBSERVABILITY_LOCAL_AUDIT=/tmp/.../audit.db \
  python -m observability read --actor auditor@bank.example
```

Useful environment overrides:

| Var | Default | Purpose |
|-----|---------|---------|
| `DEMO_AUTO=1` | off | don't wait for Enter; advance automatically (self-test / recording) |
| `DEMO_OUT` | `observability_demo.json` | JSON evidence artifact path |

The script forces an ephemeral `local` profile so inherited environment settings cannot
silently turn the offline demonstration into a cloud run.

## Portability proof

```bash
make portability-demo
```

This proves only the axes it executes. It does not prove live GCP, tamper evidence in the
local buffer, a completed on-premises WORM store, managed-bucket migration, identity
portability, or portable trace/FinOps infrastructure.

## REST variant (no script)

To show the same data over HTTP, seed a file-backed store, point the API at it, then curl
`POST/GET /v1/audit` and `/healthz`. See [`../DEMO.md`](../DEMO.md) Demo A §3 for the exact
commands and Demo B for the managed GCP stack.
