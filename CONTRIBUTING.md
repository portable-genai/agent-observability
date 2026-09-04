# Contributing to `agent-observability`

Thanks for your interest. This is an engineering-portfolio reference repo; the bar is that
every change keeps the offline gate green and respects the hexagonal boundaries.

## Setup

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"     # NO Google Cloud SDK : local/test profile
```

The default profile for development and CI is `local` (SDK-free SQLite WORM stand-in).
The managed adapters (Cloud Logging locked WORM bucket, Cloud Trace) live behind the
`[gcp]` extra and are only needed for the `gcp` profile.

## The gate (must be green before you push)

```bash
ruff check src tests            # lint
ruff format --check src tests   # formatting
mypy src                        # type-check
pytest -q                       # unit + contract
python eval/run_eval.py         # audit-integrity eval gate (exit 0)
```

All five must pass. The eval gate scores deterministic trail-integrity invariants
(`write_read_parity` / `citation_provenance` / `redaction_preserved` /
`newest_first_order`); `agent-observability` is platform eval-infrastructure, so there is no `model-quality-gate`
promotion split, by design.

## Architecture rules (hexagon)

- **The domain is pure.** No cloud/framework imports in `models.py`; every external edge
  is a `@runtime_checkable` Protocol port with `local` / `gcp` / `onprem` bindings.
- **Events arrive already redacted** (P-04): the sink never sees raw PII; do not add a
  path that logs request content.
- **GCP imports are lazy.** Inside methods or under `TYPE_CHECKING`, never at module top.
- **One construction convention.** Every adapter is `Adapter(settings: Settings)`.
- **The shared service layer comes from the commons.** Inbound S2S verification is
  `hex-service-kit` (extracted FROM this repo's reference implementation; pinned by tag
  in `pyproject.toml`, exact SHA in the lockfiles). Fix shared behaviour there, then bump
  the pin; do not re-inline a copy here.

## Conventions

- Ruff is pinned exactly; formatter output drifts between releases. Bump deliberately.
- Use obviously-fictional identifiers in fixtures and examples.
- No em-dashes in Markdown or commit messages; commits are authored solely by the repo
  owner (no co-author trailers).
