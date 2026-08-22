"""What a caller-identity scheme DECLARES about the authentication it can provide.

The exposure guard on the app object has one question to answer before it can decide anything:
can this deployment authenticate the callers it answers? Nothing else in the configuration
answers it, and two things that look like they do, do not:

* The PROFILE names an adapter family, not an authentication scheme. A deliberate ``local`` and
  an inherited one bind the same store, and an adopter's own verifying scheme can be bound under
  ``onprem`` without the profile string changing at all.
* The SERVICE-TO-SERVICE secret is a CREDENTIAL. Whether one happens to be set is not evidence
  that callers are authenticated: it says nothing about the routes that carry no credential at
  all, and under the pre-shared scheme it authenticates only "somebody who holds this string".
  Deriving the guard from it is how setting a credential came to SWITCH THE GUARD OFF.

The scheme bound to the caller-identity port is the only thing that knows, so it says so here,
and the guard reads the answer from the binding rather than inferring it from something else.

Hrz5 has NO end user. Its callers are SERVICES: agents routing an immutable audit record, and
release approvers stamping a maker-checker sign-off. So the noun here is the CALLER, where the
same rule in ``hex-service-template`` and Hrz7 says END USER. The rule itself is identical, and
so is the defect it removes.

Three answers, and the difference between the first two is the whole point:

* :data:`VERIFIED` - the scheme resolves a caller from something it VERIFIES server side (a
  signed assertion whose signature, issuer, expiry and audience it checks, followed by an
  allowlist of the callers admitted). A caller cannot name itself, so callers ARE authenticated.
* :data:`PRESHARED` - the scheme compares a symmetric string both sides already hold. Every
  holder resolves to the same anonymous identity, nothing is verified against an issuer, and
  under the offline profile the route is OPEN when no string is configured. That is a demo
  posture, not authentication, however carefully the comparison is done.
* :data:`UNIMPLEMENTED` - the scheme resolves nobody at all: a portability placeholder waiting
  for the adopter's own verifier. Nobody can be authenticated, so nothing is.

A scheme that declares NOTHING is read as :data:`PRESHARED`, never :data:`VERIFIED`. Silence is
not a claim to verify anything, and a guard that reads silence as "authenticated" switches itself
off for every scheme somebody forgot to annotate, which is the fail-open shape this module exists
to remove.
"""

from __future__ import annotations

#: The scheme verifies a server-side assertion; the caller cannot assert who it is.
VERIFIED = "verified"
#: The scheme compares a symmetric string both sides hold. Useful offline, not authentication.
PRESHARED = "preshared-key"
#: The scheme resolves nobody: a placeholder for a verifier not yet bound.
UNIMPLEMENTED = "unimplemented"

#: Every declaration this service understands. Anything else is read as :data:`PRESHARED`.
CALLER_AUTH_KINDS: frozenset[str] = frozenset({VERIFIED, PRESHARED, UNIMPLEMENTED})

#: The class attribute a caller-identity scheme sets to one of the values above. A CLASS
#: attribute, not an instance one, because the posture has to be readable WITHOUT constructing
#: anything: it is resolved at import, before any request, and a posture that can only be
#: computed by constructing something disappears exactly when it matters most.
CALLER_AUTH_ATTR = "caller_auth"


def declared_caller_auth(scheme: object) -> str:
    """What ``scheme`` (a class or an instance) declares, defaulting to :data:`PRESHARED`.

    The default is the fail-closed one in BOTH directions this value is read: it withholds the
    "authenticated" verdict the exposure guard would relax on, and it withholds the OIDC
    verification path in ``api/security.py``. An unrecognised value lands in the same place, so
    a typo in a declaration cannot read as a verification claim.
    """
    declared = getattr(scheme, CALLER_AUTH_ATTR, None)
    if isinstance(declared, str) and declared in CALLER_AUTH_KINDS:
        return declared
    return PRESHARED


class PortabilityPlaceholderError(NotImplementedError):
    """A migration placeholder was called on a SERVING path, and the answer says so.

    A bare :class:`NotImplementedError` is not something FastAPI knows how to answer, so it
    escaped every handler and became a bare ``500 Internal Server Error`` with no body: an
    operator got a stack trace in the logs and a caller got nothing at all. Executed against this
    repo before the fix, an AUTHENTICATED ``POST /v1/audit`` and ``GET /v1/audit`` under
    ``OBSERVABILITY_PROFILE=onprem`` both answered 500.

    Still a :class:`NotImplementedError`, because "every method of the exit family raises
    ``NotImplementedError``" is a claim ``tests/test_adapter_parity.py`` and
    ``scripts/portability_demo.py`` both make about EVERY port, and it stays true.

    501, not 5xx noise and not 401: nothing is implemented here yet, no credential the caller
    could have presented would have helped, and the status says exactly that.
    """

    #: The status the API answers with.
    http_status: int = 501
