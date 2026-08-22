"""On-prem placeholder for ``AuditSinkPort`` — the Google Distributed Cloud target.

One of the reversibility (P-02) migration placeholders: in the managed profile this port
binds to the Cloud Logging locked-WORM-bucket adapter; switching ``profile`` to ``onprem``
rebinds it here. The adapter constructs cleanly with **no external dependencies** and
structurally satisfies the same Protocol as the managed adapter, so the contract tests
prove interface parity.

``record`` deliberately raises rather than discarding the event: an unimplemented audit
sink must never silently drop a compliance record, so porting on-premise *must* supply a
real immutable (WORM) audit store. Filling in these bodies is the only change required;
the core domain logic is unchanged.

The refusal has a SHAPE, and the shape is the point. These methods sit on a SERVING path, and
a bare ``NotImplementedError`` is not something FastAPI knows how to answer: it escaped every
handler and became ``500 Internal Server Error`` with no body, so a caller learned nothing and
an operator learned nothing. They now raise
:class:`~observability.ports.identity.PortabilityPlaceholderError`, which carries a 501 and a
reason and is answered as such by ``api/app.py``. It is still a :class:`NotImplementedError`,
because "every method of the exit family raises ``NotImplementedError``" is a claim
``tests/test_adapter_parity.py`` and ``scripts/portability_demo.py`` both make, and it stays
true.
"""

from __future__ import annotations

from ...config import Settings
from ...models import AuditEvent
from ...ports.identity import PortabilityPlaceholderError

_MESSAGE = (
    "On-prem AuditSinkPort adapter is a migration placeholder; implement against your "
    "on-premise platform's immutable (WORM) audit store. Core domain logic is unchanged."
)


class OnPremAuditAdapter:
    """Placeholder audit-sink adapter for the on-prem (Google Distributed Cloud) profile."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def record(self, event: AuditEvent) -> None:
        raise PortabilityPlaceholderError(_MESSAGE)

    def record_once(
        self,
        event: AuditEvent,
        *,
        idempotency_key: str,
        payload_digest: str,
    ) -> str:
        raise PortabilityPlaceholderError(_MESSAGE)

    def get(self, event_id: str) -> AuditEvent | None:
        raise PortabilityPlaceholderError(_MESSAGE)

    def read_recent(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 50,
    ) -> list[AuditEvent]:
        raise PortabilityPlaceholderError(_MESSAGE)
