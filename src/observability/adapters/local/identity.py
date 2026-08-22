"""Local caller-identity scheme: a pre-shared string, or nothing at all.

The offline profile authenticates a calling service with ``OBSERVABILITY_S2S_TOKEN``, compared
in constant time by the commons, and leaves the ingest OPEN when that variable is unset so the
gate runs with zero secrets on loopback.

Neither state is authentication of an identity. Unset, anybody may write. Set, anybody holding
the string may write, and they all resolve to the same anonymous ``local-demo-service``: there
is no issuer, no signature and no allowlist, so the WORM trail records that a holder of the
string wrote a row, not who did. The declaration below says that plainly, and it is what keeps
this service on loopback whatever the variable is set to.
"""

from __future__ import annotations

from ...ports.identity import PRESHARED


class SharedSecretCallerIdentity:
    """The shared-secret S2S scheme: symmetric, anonymous, and open when unconfigured."""

    #: A string both sides already hold, verified against no issuer. See ``ports/identity.py``.
    caller_auth = PRESHARED
