"""On-prem adapter family — fail-fast Google Distributed Cloud migration placeholders.

Every adapter here constructs cleanly with a single :class:`Settings` argument and
structurally satisfies its port Protocol, so the contract tests prove interface parity,
but every method raises ``NotImplementedError``. Switching ``OBSERVABILITY_PROFILE`` to
``onprem`` rebinds the ports here; filling in the bodies against the on-premise platform
is the only change required, with the core domain unchanged (P-02 reversibility). No
third-party product is named.
"""

from __future__ import annotations
