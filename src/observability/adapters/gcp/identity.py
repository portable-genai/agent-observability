"""GCP caller-identity scheme: a Google-signed OIDC ID token, verified server side.

The only scheme in the shipped set that declares :data:`VERIFIED`, and it earns it in the
commons dependency this binding selects (``hex_service_kit.web.make_require_service_caller``):
the bearer's signature, issuer, expiry and audience (``OBSERVABILITY_S2S_AUDIENCE``) are checked
before any claim is read, and the verified caller service account is then matched against the
``OBSERVABILITY_S2S_ALLOWED_CALLERS`` allowlist. Both halves of that policy are read in three
states and refuse with a 503 when unset, so an unconfigured deployment authenticates nobody
rather than skipping the check.

A caller cannot name itself here, so this is the one binding that lets the loopback exposure
guard stand down: the platform fronts the deployment, and every data route refuses a caller with
no verified assertion on its own.

The verification libraries are imported by the commons, lazily, so this module carries no GCP
SDK import and the offline profile imports it with nothing installed.
"""

from __future__ import annotations

from ...ports.identity import VERIFIED


class OidcCallerIdentity:
    """The Google-signed OIDC ID token scheme, with the caller allowlist behind it."""

    #: A signed assertion, verified against an issuer. See ``ports/identity.py``.
    caller_auth = VERIFIED
