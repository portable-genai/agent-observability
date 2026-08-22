"""The exposure guard is derived from the CALLER-IDENTITY BINDING, and from nothing else.

The defect this file is the standing guard for: the guard's posture must never read

    profile chosen AND profile == local AND OBSERVABILITY_S2S_TOKEN unset

so SETTING the service-to-service secret switched the guard OFF. Executed against this repo with
`OBSERVABILITY_PROFILE=local` chosen deliberately, the token set (an ordinary deployment shape)
and uvicorn bound to `0.0.0.0`, a peer at another address on the LAN carrying no Authorization
header read `/healthz` and the whole `/v1/capabilities` manifest off a laptop demo. The same
expression also let the entire `onprem` profile out of the guard, which answered a LAN peer the
same two routes with no credential and no secret at all.

The cause is worth stating precisely, because widening the boolean would have hidden it rather
than fixed it: **whether a credential is SET is not evidence that this deployment can
authenticate its callers.** It says nothing about `/healthz` and `/v1/capabilities`, which carry
no credential by design, and under the pre-shared scheme it authenticates only "somebody holding
this string". So the guard now asks the only thing that knows: the caller-identity scheme the
active binding names, which DECLARES whether it verifies its caller server side against an
issuer (`ports/identity.py`, bound in `api/security.py`).

Hrz5 has no end user; its callers are services. That is the one word that differs from the same
guard in `hex-service-template` and Hrz7, where the noun is END USER. The rule is identical.

Four things are proved here, and the last is what stops the defect returning in a different
shape:

1. every shipped scheme declares, explicitly, what it can authenticate;
2. `SECURE_PROFILES` is DERIVED from those declarations, so the profiles that take the verifying
   path and the profiles the guard stands down for cannot drift apart;
3. the declaration is what the posture reports, including through a REBINDING (the on-premises
   path) and when the binding cannot be resolved at all, where it fails closed;
4. the guard's argument, expanded through the module constants AND functions it names, mentions
   no service credential anywhere. A scanner with a mutant that must go red, because the original
   defect was one indirection deep and would pass any check that only read the call site.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from observability.adapters.gcp.identity import OidcCallerIdentity
from observability.adapters.local.identity import SharedSecretCallerIdentity
from observability.adapters.onprem.audit import OnPremAuditAdapter
from observability.adapters.onprem.identity import OnPremCallerIdentity
from observability.api.app import create_app
from observability.api.security import (
    CALLER_IDENTITY_BINDINGS,
    SECURE_PROFILES,
    caller_auth_kind,
    caller_identity_class,
)
from observability.config import RUNTIME_PROFILES, LocalSettings, Settings
from observability.ports.identity import (
    CALLER_AUTH_ATTR,
    CALLER_AUTH_KINDS,
    PRESHARED,
    UNIMPLEMENTED,
    VERIFIED,
    PortabilityPlaceholderError,
    declared_caller_auth,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_MODULE = _REPO_ROOT / "src" / "observability" / "api" / "app.py"

#: The guard call whose argument must never be derived from a credential.
_GUARD_CALL = "add_loopback_exposure_guard"

#: Anything naming a SERVICE credential. The guard bounds the whole app, including routes that
#: carry no credential at all, so none of these may appear anywhere in the expression that
#: decides whether it is on, at any depth.
_CREDENTIAL_MARKERS: tuple[str, ...] = ("S2S", "TOKEN", "SECRET", "BEARER")

_ADAPTER_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}


# --------------------------------------------------------------------------- #
# 1. Every shipped scheme declares what it does, explicitly.
# --------------------------------------------------------------------------- #
def test_the_shared_secret_scheme_declares_a_preshared_key() -> None:
    """A symmetric string both sides hold is not a verified identity, and cannot become one."""
    assert declared_caller_auth(SharedSecretCallerIdentity) == PRESHARED


def test_the_oidc_scheme_declares_that_it_verifies() -> None:
    """The one shipped scheme that checks a signature and an issuer before admitting a caller."""
    assert declared_caller_auth(OidcCallerIdentity) == VERIFIED


def test_the_onprem_placeholder_declares_that_it_verifies_nothing() -> None:
    assert declared_caller_auth(OnPremCallerIdentity) == UNIMPLEMENTED


@pytest.mark.parametrize("profile", sorted(RUNTIME_PROFILES))
def test_every_bound_scheme_declares_explicitly(profile: str) -> None:
    """A new scheme must SAY what it does; inheriting the safe default silently is not enough.

    The default exists so that an unannotated scheme cannot claim to verify anything. It is not
    a licence to leave the question unanswered: the answer decides both which authentication
    path the profile takes and whether the service may be reached from anywhere but loopback.
    """
    scheme = caller_identity_class(profile)
    declared = [klass for klass in scheme.__mro__ if CALLER_AUTH_ATTR in vars(klass)]
    assert declared, (
        f"{scheme.__name__} (the {profile} caller-identity binding) sets no {CALLER_AUTH_ATTR}. "
        f"Declare one of {sorted(CALLER_AUTH_KINDS)} on the class: the exposure guard and the "
        "S2S dependency both read it, and silence is read as a pre-shared key."
    )
    assert declared_caller_auth(scheme) in CALLER_AUTH_KINDS


def test_every_profile_has_a_caller_identity_binding() -> None:
    """A profile with no scheme bound would fail closed, but silently. Name all of them."""
    assert set(CALLER_IDENTITY_BINDINGS) == RUNTIME_PROFILES


# --------------------------------------------------------------------------- #
# 2. The verifying path and the guard's exception are the SAME set.
# --------------------------------------------------------------------------- #
def test_the_secure_profiles_are_exactly_the_ones_that_declare_verified() -> None:
    """Two lists that must agree are one list, derived. This asserts what it derives to.

    `SECURE_PROFILES` selects the OIDC path in the S2S dependency and the same declarations
    stand the exposure guard down. Written out by hand in two places they would eventually
    disagree, and the disagreement would be a profile that authenticates with a shared secret
    while being served to the whole network.
    """
    assert SECURE_PROFILES == ("gcp",)
    for profile in RUNTIME_PROFILES:
        verified = caller_auth_kind(profile) == VERIFIED
        assert verified == (profile in SECURE_PROFILES), (
            f"{profile} declares {caller_auth_kind(profile)!r} but "
            f"{'is' if profile in SECURE_PROFILES else 'is not'} in SECURE_PROFILES"
        )


# --------------------------------------------------------------------------- #
# 3. The declaration is what the posture reports, including through a rebinding.
# --------------------------------------------------------------------------- #
class _UndeclaredScheme:
    """A scheme that says nothing at all."""


class _MisdeclaredScheme:
    """A scheme whose declaration is a typo, which must not read as a verification claim."""

    caller_auth = "Verified"


@pytest.mark.parametrize("scheme", [_UndeclaredScheme, _MisdeclaredScheme, object()])
def test_silence_and_typos_are_read_as_a_preshared_key(scheme: object) -> None:
    """The fail-closed default, in the only direction that matters: never VERIFIED."""
    assert declared_caller_auth(scheme) == PRESHARED


@pytest.mark.parametrize(
    ("profile", "expected"),
    [("local", PRESHARED), ("gcp", VERIFIED), ("onprem", UNIMPLEMENTED)],
)
def test_the_posture_follows_the_profile_binding(profile: str, expected: str) -> None:
    assert caller_auth_kind(profile) == expected


def test_the_posture_follows_a_REBOUND_scheme_not_the_profile_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The on-premises migration path: bind a real verifier and the posture changes with it.

    This is why the guard reads the BINDING rather than the profile string. An adopter who wires
    their own verifying scheme under `onprem` has an authenticated service, and a guard that
    keyed off the word "onprem" would confine it to loopback forever with no way out but the
    insecure-demo opt-out.
    """
    monkeypatch.setitem(
        CALLER_IDENTITY_BINDINGS,
        "onprem",
        "observability.adapters.gcp.identity:OidcCallerIdentity",
    )
    assert caller_auth_kind("onprem") == VERIFIED
    settings = Settings(
        profile="onprem",
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )
    client = TestClient(create_app(settings), client=("192.168.1.37", 51234))
    assert client.get("/healthz").status_code == 200, "the rebinding must lift the bound"


def test_an_unresolvable_binding_fails_CLOSED_rather_than_raising_past_the_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A guard that switches off because a lookup raised is a guard that fails open."""
    monkeypatch.setitem(CALLER_IDENTITY_BINDINGS, "local", "observability.nope:Missing")
    assert caller_auth_kind("local") == PRESHARED
    with pytest.raises(ModuleNotFoundError):
        caller_identity_class("local")


# --------------------------------------------------------------------------- #
# The on-premises placeholder refuses with a status and a reason, not a bare 500.
# --------------------------------------------------------------------------- #
def test_the_onprem_audit_placeholder_answers_501_with_a_reason() -> None:
    """An AUTHENTICATED write under `onprem` must not answer a bare 500.

    Both ancestries are load-bearing. As a `PortabilityPlaceholderError` it carries a status and
    a reason to the caller; as a `NotImplementedError` it keeps the exit family's uniform
    refusal, which `tests/test_adapter_parity.py` and `scripts/portability_demo.py` both assert
    for every method of every port at once.
    """
    settings = Settings(profile="onprem", adapters=_ADAPTER_BINDINGS)
    adapter = OnPremAuditAdapter(settings)
    with pytest.raises(PortabilityPlaceholderError) as caught:
        adapter.get("any-event")
    error = caught.value
    assert isinstance(error, NotImplementedError), "the exit family's uniform refusal stands"
    assert error.http_status == 501, "no credential would have helped, so 4xx would be a lie"
    assert "WORM" in str(error)


def test_the_serving_path_answers_the_placeholder_rather_than_a_bare_500() -> None:
    """The refusal has to reach the CALLER, not just the logs, so the app maps it.

    The unbound port is reached by binding the on-prem placeholder under the offline profile,
    which is the shortest honest route to the case: on `onprem` proper, the S2S dependency and
    the exposure guard both refuse first, so the request would never arrive at the port and the
    bare 500 would stay invisible in exactly the deployment that has it.
    """
    unbound = {"audit": {**_ADAPTER_BINDINGS["audit"]}}
    unbound["audit"]["local"] = "observability.adapters.onprem.audit:OnPremAuditAdapter"
    settings = Settings(
        profile="local",
        local=LocalSettings(audit_path=":memory:"),
        adapters=unbound,
    )
    client = TestClient(create_app(settings), client=("127.0.0.1", 51234))
    response = client.get("/v1/audit/some-event")
    assert response.status_code == 501, "a placeholder on a serving path must not be a bare 500"
    assert "migration placeholder" in response.json()["detail"]


# --------------------------------------------------------------------------- #
# 4. The guard's argument names no credential, at any depth.
# --------------------------------------------------------------------------- #
class _StripDocstrings(ast.NodeTransformer):
    """Drop every docstring from a subtree before it is scanned.

    The scan looks for the NAME of a credential in what the guard's posture reaches, and a
    docstring is prose, not a read. Without this, `_is_unauthenticated_posture`'s own docstring,
    which exists precisely to say that `OBSERVABILITY_S2S_TOKEN` is NOT in the expression, would
    make the scanner fail the build for saying so.
    """

    def _strip(self, node: ast.AST) -> ast.AST:
        body = getattr(node, "body", None)
        first = body[0] if isinstance(body, list) and body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]  # type: ignore[attr-defined,index]
        return self.generic_visit(node)

    visit_FunctionDef = _strip
    visit_AsyncFunctionDef = _strip
    visit_ClassDef = _strip
    visit_Module = _strip


def _module_definitions(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = <expr>`` assignments AND function bodies, as source text.

    Functions as well as constants, because this repo's posture is computed by one
    (``_is_unauthenticated_posture``) rather than assigned to a name. A scanner that only
    followed assignments would stop at the call site and see nothing.
    """
    found: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                found[target.id] = ast.unparse(node.value)
        elif isinstance(node, ast.FunctionDef):
            stripped = _StripDocstrings().visit(ast.parse(ast.unparse(node)))
            found[node.name] = ast.unparse(stripped)
    return found


def guard_posture_source(source: str) -> str:
    """Everything the exposure guard's ``unauthenticated`` argument reaches, as one blob.

    Public, and transitive on purpose. The defect is one indirection deep: the call
    site read ``unauthenticated=_is_unauthenticated_posture(container.settings)`` and the
    credential was named inside that function. A check that only read the call site would have
    passed it.
    """
    tree = ast.parse(source)
    definitions = _module_definitions(tree)
    expressions: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith(_GUARD_CALL):
            expressions += [
                ast.unparse(kw.value) for kw in node.keywords if kw.arg == "unauthenticated"
            ]
    assert expressions, f"no {_GUARD_CALL}(unauthenticated=...) call found"
    seen: set[str] = set()
    reached = list(expressions)
    pending = list(expressions)
    while pending:
        for name_node in ast.walk(ast.parse(pending.pop())):
            if isinstance(name_node, ast.Name) and name_node.id not in seen:
                seen.add(name_node.id)
                if name_node.id in definitions:
                    reached.append(definitions[name_node.id])
                    pending.append(definitions[name_node.id])
    return "\n".join(reached + sorted(seen))


def test_the_exposure_guard_reads_no_service_credential() -> None:
    """The defect, stated as a rule: a credential may not decide whether the guard is on."""
    reached = guard_posture_source(_APP_MODULE.read_text(encoding="utf-8")).upper()
    offenders = [marker for marker in _CREDENTIAL_MARKERS if marker in reached]
    assert offenders == [], (
        f"the exposure guard's posture reaches {offenders}. Whether a credential is SET is not "
        "evidence that this deployment can authenticate its callers, and it is no evidence at "
        "all about the routes that carry no credential. Derive the posture from the "
        "caller-identity binding (api.security.caller_auth_kind) instead."
    )


def test_the_exposure_guard_is_derived_from_the_caller_identity_binding() -> None:
    """Not merely "no credential": the posture must come from the thing that actually knows."""
    reached = guard_posture_source(_APP_MODULE.read_text(encoding="utf-8"))
    assert "caller_auth_kind" in reached, (
        "the guard no longer reads the caller-identity binding, so nothing checks whether this "
        "deployment can authenticate anybody at all"
    )


#: The defect exactly as it was written in this repo, one indirection deep. A scanner nobody
#: proved can find anything is a green tick over an empty set.
_MUTANT = (
    "_TOKEN_ENV = 'OBSERVABILITY_S2S_TOKEN'\n"
    "def _is_unauthenticated_posture(settings):\n"
    "    if not settings.service_auth_configured:\n"
    "        return True\n"
    "    return settings.profile == 'local' and read_env_setting(_TOKEN_ENV).is_unset\n"
    "add_loopback_exposure_guard(\n"
    "    app,\n"
    "    unauthenticated=_is_unauthenticated_posture(container.settings),\n"
    "    insecure_demo_env=_INSECURE_DEMO_ENV,\n"
    "    posture=container.settings.exposure_profile,\n"
    ")\n"
)


def test_the_scan_finds_the_defect_it_was_written_for() -> None:
    reached = guard_posture_source(_MUTANT).upper()
    caught = {marker for marker in _CREDENTIAL_MARKERS if marker in reached}
    assert caught == {"S2S", "TOKEN"}, (
        "the scan no longer finds the credential in the expression the defect was written as, "
        "so a green result from it means nothing"
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
