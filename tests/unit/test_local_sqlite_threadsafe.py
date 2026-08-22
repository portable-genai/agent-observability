"""Concurrency regression: the local SQLite audit adapter is safe across worker threads.

Under ``local serve`` the FastAPI container is process-wide (one
:class:`~observability.adapters.local.audit.LocalAppendOnlyAuditAdapter` instance holding
one ``sqlite3`` connection) while the sync endpoints run in Starlette's anyio worker
threadpool. A request handled on a worker thread therefore calls ``record()`` /
``read_recent()`` / ``count()`` on a connection opened by a *different* thread (the one
that built the adapter). Without ``check_same_thread=False`` plus a lock, sqlite3 raises
"SQLite objects created in a thread can only be used in that same thread", dropping the
WORM audit event and 500-ing the request under concurrency.

This test constructs the adapter **once** with ``:memory:`` settings and then drives
interleaved writes and reads from many threads via a ``ThreadPoolExecutor``, asserting no
exception is raised and the final row count is exact. It fails before the
``check_same_thread=False`` + lock fix (with the cross-thread ``ProgrammingError``) and
passes after it.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable

from observability.adapters.local.audit import LocalAppendOnlyAuditAdapter
from observability.config import LocalSettings, Settings
from observability.models import AuditEvent, Citation, Decision

_THREADS = 8
_PER_THREAD = 25
_TOTAL = _THREADS * _PER_THREAD


def _settings() -> Settings:
    # A single shared in-memory connection (in-memory DBs are per-connection, so the one
    # connection opened in __init__ is the one every worker thread must reach). max_events
    # stays at the default 1000, comfortably above _TOTAL, so the ring buffer never prunes
    # and the final count is exactly _TOTAL.
    return Settings(profile="local", local=LocalSettings(audit_path=":memory:"))


def _drive[T](fn: Callable[[int], T]) -> list[T]:
    """Run ``fn(i)`` for i in range(_TOTAL) across a thread pool, raising the first
    exception any worker hit (so a cross-thread sqlite3 error fails the test)."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        futures = [pool.submit(fn, i) for i in range(_TOTAL)]
        return [f.result() for f in concurrent.futures.as_completed(futures)]


def test_audit_adapter_is_thread_safe() -> None:
    adapter = LocalAppendOnlyAuditAdapter(_settings())

    def work(i: int) -> int:
        adapter.record(
            AuditEvent(
                action="ask",
                actor=f"user-{i}",
                decision=Decision.ALLOWED,
                redacted_prompt="q",
                redacted_response="a",
                citations=(
                    Citation(
                        source_id=f"reg-{i}",
                        regulator="MAS",
                        jurisdiction="SG",
                        title=f"Notice {i}",
                        url=f"https://mas.test/{i}",
                        version="2026",
                        page=1,
                    ),
                ),
            )
        )
        # Interleave reads on the same connection from the worker thread too.
        adapter.read_recent(limit=5)
        return adapter.count()

    results = _drive(work)

    # Every record()/read_recent()/count() ran on a worker thread without a cross-thread
    # ProgrammingError, and the append-only store holds exactly one row per call.
    assert all(r >= 1 for r in results)
    assert adapter.count() == _TOTAL
    assert len(adapter.read_recent(limit=_TOTAL)) == _TOTAL
