"""On-prem caller-identity scheme: the fail-fast placeholder for the adopter's own verifier.

Nothing verifies a caller on the Google Distributed Cloud migration target until the adopter
binds something that does, so this declares :data:`UNIMPLEMENTED` and the loopback exposure
guard keeps the deployment off the network.

That bound is lifted by BINDING a verifier, not by setting a secret. Point
``api.security.CALLER_IDENTITY_BINDINGS['onprem']`` at a scheme class declaring
``caller_auth = VERIFIED`` (see ``docs/onprem-migration.md``) and two things follow from that one
edit: the S2S dependency takes the verifying path for the ``onprem`` profile, and the exposure
guard stands down. Declaring ``VERIFIED`` is a claim that the scheme resolves a caller from
something it checks SERVER SIDE, against an issuer, and that a caller cannot name itself.
"""

from __future__ import annotations

from ...ports.identity import UNIMPLEMENTED


class OnPremCallerIdentity:
    """Placeholder caller-identity scheme: nothing is bound, so nobody is verified."""

    #: Resolves nobody until a verifier is bound. See ``ports/identity.py``.
    caller_auth = UNIMPLEMENTED
