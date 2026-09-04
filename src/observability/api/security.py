"""Service-to-service (S2S) auth: authenticate the *calling service*, fail-closed.

agent-observability's ``POST /v1/audit`` is the platform WORM ingest: every agent routes its
immutable audit record here. Before this module nothing authenticated the caller. The shared S2S
contract is:

* Callers present ``Authorization: Bearer <token>``.
* A DELIBERATELY chosen ``local`` profile, and EXACTLY that string: a static shared secret
  from ``OBSERVABILITY_S2S_TOKEN``, compared in constant time. When the env var is UNSET the
  API stays open (loopback dev only), so the offline test gate runs with zero secrets; when
  SET, a request without the matching token is 401, and when set to an EMPTY value it is a
  503 (an empty secret authenticates nobody).
* ``gcp`` profile: the bearer is a Google-signed OIDC ID token; its signature, issuer,
  expiry and audience (``OBSERVABILITY_S2S_AUDIENCE``) are verified, then the caller service
  account is authorized against the ``OBSERVABILITY_S2S_ALLOWED_CALLERS`` allowlist. The
  google verification libs are imported lazily so the offline profile imports this module
  with no GCP SDK installed.
* **Anything else**, including ``onprem`` and an UNSET ``OBSERVABILITY_PROFILE``: the
  shared-secret path with NO opening, so an unset secret is a 503. A profile nobody chose is
  not consent to serve the audit ingest unauthenticated. (A mis-capitalised ``Local`` never
  reaches here at all: :func:`observability.config.resolve_profile` refuses it at import.)

The profile this module matches on is ``settings.exposure_profile``, NOT ``settings.profile``.
The zero-secret opening is a RELAXATION, and the two differ in exactly the case that matters:
with ``OBSERVABILITY_PROFILE`` unset, ``profile`` is still ``local`` (the adapters have to
bind something offline) while ``exposure_profile`` is ``unconfigured``, which opens for
nothing. Before that split, a run nobody had configured accepted a forged audit record with
no bearer token, because the two-state YAML default made "unset" and "chose local" the same
string.

``/healthz`` is intentionally unauthenticated (liveness); the loopback exposure guard in
``api/app.py`` is what keeps it off the LAN while the posture is unauthenticated.

**Sourced from the shared ``hex-service-kit`` commons.** The verification logic lives in the commons
rather than as a hand-rolled copy here, and delegates to
:func:`hex_service_kit.web.make_require_service_caller` with this repo's env-var names and profile
rule passed as arguments, exactly as agent-registry's gateway does. The copy had drifted into a
fail-open: it took the local shared-secret branch for every profile that was not ``gcp``, so
``onprem`` and any typo'd profile served the ingest to an unauthenticated caller whenever the token
was unset. The commons opens only on an exact ``local`` match, and checks the identity policy before
the token under the secure profile. A fix to the S2S rule is now a version bump of the package
rather than an N-repo edit.

Both dependencies here share ``OBSERVABILITY_S2S_TOKEN`` and differ only in which allowlist
authorizes the caller under the secure profile: the general ingest uses
``OBSERVABILITY_S2S_ALLOWED_CALLERS``, and the maker-checker release-approval route requires
membership of the narrower ``OBSERVABILITY_RELEASE_APPROVERS``.

**Which scheme a profile takes is a BINDING, not a literal**, and the same binding is what the
loopback exposure guard in ``api/app.py`` reads. :data:`CALLER_IDENTITY_BINDINGS` names one
scheme class per profile and each class DECLARES what it can authenticate
(``ports/identity.py``); :data:`SECURE_PROFILES` is derived from those declarations rather than
written out, so the profiles that take the verifying path and the profiles the guard stands down
for can never drift apart. Rebinding a profile to a verifying scheme therefore changes both at
once, which is the documented way an on-premises deployment gets off loopback.
"""

from __future__ import annotations

import importlib

from fastapi import Depends, Request
from hex_service_kit.web import make_require_service_caller

from ..ports.identity import PRESHARED, VERIFIED, declared_caller_auth

_TOKEN_ENV = "OBSERVABILITY_S2S_TOKEN"  # noqa: S105 - env var NAME, not a secret value
_ALLOWED_CALLERS_ENV = "OBSERVABILITY_S2S_ALLOWED_CALLERS"
_AUDIENCE_ENV = "OBSERVABILITY_S2S_AUDIENCE"
_APPROVERS_ENV = "OBSERVABILITY_RELEASE_APPROVERS"

#: profile -> the ``module:Class`` naming the caller-identity scheme it binds. Kept in its own
#: exact map rather than in ``settings.adapters``: those are persistence adapters the container
#: CONSTRUCTS and Protocol-checks, and an authentication choice must never be able to change the
#: data profile (or be changed by it) as a side effect. This is the same separation
#: human-review-console keeps
#: between its runtime bindings and its identity map.
CALLER_IDENTITY_BINDINGS: dict[str, str] = {
    "gcp": "observability.adapters.gcp.identity:OidcCallerIdentity",
    "local": "observability.adapters.local.identity:SharedSecretCallerIdentity",
    "onprem": "observability.adapters.onprem.identity:OnPremCallerIdentity",
}


def caller_identity_class(profile: str) -> type:
    """The caller-identity scheme CLASS bound to ``profile``, resolved without constructing it.

    Nothing is constructed because nothing needs to be: the verification itself lives in the
    commons dependency below, and the posture has to be readable at import, before any request
    and before any container exists.
    """
    target = CALLER_IDENTITY_BINDINGS[profile]
    module_path, _, class_name = target.partition(":")
    resolved = getattr(importlib.import_module(module_path), class_name)
    if not isinstance(resolved, type):
        raise TypeError(f"caller-identity binding {target!r} does not name a class")
    return resolved


def caller_auth_kind(profile: str) -> str:
    """What the scheme bound to ``profile`` declares it can authenticate.

    This is the one question "can this deployment authenticate the callers it answers?" reduces
    to. See :mod:`observability.ports.identity` for why neither the profile string on its own nor
    the presence of a service credential can answer it.

    Any failure to establish the answer resolves to
    :data:`~observability.ports.identity.PRESHARED`, the non-verifying default. A guard that
    switches OFF because a lookup raised is a guard that fails open, and nothing is lost by
    failing closed here: an unresolvable binding still surfaces loudly, at import, where
    :data:`SECURE_PROFILES` is computed.
    """
    try:
        return declared_caller_auth(caller_identity_class(profile))
    except Exception:  # noqa: BLE001 - a guard that fails open on a lookup error is no guard
        return PRESHARED


#: The profiles whose bound scheme VERIFIES its caller, and therefore the profiles that take the
#: OIDC path below. DERIVED from the bindings, never written out: the exposure guard reads the
#: same declarations, and a hand-maintained second list would eventually disagree with them.
#: Out of the box that is ``("gcp",)``; this service has no ``platform`` profile, and ``onprem``
#: is the fail-fast migration placeholder until an adopter binds a verifier.
SECURE_PROFILES: tuple[str, ...] = tuple(
    sorted(p for p in CALLER_IDENTITY_BINDINGS if caller_auth_kind(p) == VERIFIED)
)


def _profile(request: Request) -> str:
    """The EXPOSURE profile, so an unset ``OBSERVABILITY_PROFILE`` opens for nothing."""
    return str(request.app.state.settings.exposure_profile)


#: FastAPI dependency: authenticate the calling service by profile, fail-closed.
require_service_caller = make_require_service_caller(
    _profile,
    token_env=_TOKEN_ENV,
    allowed_callers_env=_ALLOWED_CALLERS_ENV,
    audience_env=_AUDIENCE_ENV,
    secure_profiles=SECURE_PROFILES,
)

#: FastAPI dependency for the maker-checker release-approval route: the same verification
#: against the narrower approver allowlist, so an ordinary audit writer cannot stamp an
#: approval.
require_release_approver = make_require_service_caller(
    _profile,
    token_env=_TOKEN_ENV,
    allowed_callers_env=_APPROVERS_ENV,
    audience_env=_AUDIENCE_ENV,
    secure_profiles=SECURE_PROFILES,
)

# Reusable dependency for route decorators.
ServiceCaller = Depends(require_service_caller)
