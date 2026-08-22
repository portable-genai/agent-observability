"""The profile has ONE source of truth, it fails closed on an unset variable, and it is
validated at import so a typo cannot serve.

Mirrors Hrz7 (`human-review-console/tests/test_profile_single_source.py`), which is
the reference shape for this class of fail-open, and extended with the two defects an
adversarial verifier PROVED by execution against this repo:

1. `config/settings.yaml` resolved the profile as `${OBSERVABILITY_PROFILE:-local}`, a
   TWO-state read. With `OBSERVABILITY_PROFILE` and `OBSERVABILITY_S2S_TOKEN` both unset,
   `POST /v1/audit` returned 202 and wrote an attacker-chosen row into the WORM trail: the
   absence of a choice was indistinguishable from a deliberate `local`, and `local` is the
   one profile whose ingest opens for an unset service token.
2. Nothing validated the variable at boot. `OBSERVABILITY_PROFILE=Local` imported cleanly and
   a LAN peer at 192.168.1.50 got 200 on `/healthz`, where an unset or exactly-`local`
   profile correctly got 503: `_is_unauthenticated_posture` compares `== "local"`, so the
   capitalisation typo silently DISABLED the exposure guard rather than tripping it.

The drift guard is part of the fix, not decoration: any module that reads the variable
directly can reintroduce the whole class in one line, so only `config.resolve_profile` may.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from hex_service_kit import ConfiguredEmptyError

from helpers import sample_event
from observability.api.app import create_app
from observability.api.security import _TOKEN_ENV
from observability.config import (
    PROFILE_ENV,
    RUNTIME_PROFILES,
    UNCONSENTED_PROFILE,
    LocalSettings,
    ProfileError,
    Settings,
    resolve_profile,
)

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src" / "observability"
_CONFIG = _SRC / "config.py"

_LAN_PEER = ("192.168.1.50", 51234)
_LOOPBACK_PEER = ("127.0.0.1", 51234)

_ADAPTER_BINDINGS = {
    "audit": {
        "gcp": "observability.adapters.gcp.cloud_logging_audit:CloudLoggingAuditAdapter",
        "local": "observability.adapters.local.audit:LocalAppendOnlyAuditAdapter",
        "onprem": "observability.adapters.onprem.audit:OnPremAuditAdapter",
    }
}

#: Every capitalisation variant the verifier ran, plus a value nothing binds.
_MIS_CAPITALISED = ("Local", "LOCAL", "lOcal", "GCP", "OnPrem", "bogus")

#: Surrounding whitespace is a different state from a typo and lands the other way: it is
#: STRIPPED to the profile the operator meant, exactly as the commons strips the bind host.
#: It belonged in the same defect, though: the YAML interpolation never stripped, so
#: `OBSERVABILITY_PROFILE=' local'` reached every posture comparison as a string that is not
#: `local` and silently disabled the exposure guard, just as `Local` did.
_WHITESPACE_WRAPPED = (" local", "local ", " local ", "\tgcp\n")


def _python_sources() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if p != _CONFIG)


# --------------------------------------------------------------------------- #
# The drift guard: only the resolver may read the variable
# --------------------------------------------------------------------------- #
def test_only_the_resolver_reads_the_profile_variable_from_the_environment() -> None:
    offenders = []
    for path in _python_sources():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if re.search(r"(os\.environ|os\.getenv)[^\n]*PROFILE", line):
                offenders.append(f"{path.relative_to(_SRC)}:{number}: {line.strip()}")
    assert not offenders, (
        "these modules re-derive the profile instead of taking it from config.resolve_profile, "
        f"so an unset {PROFILE_ENV} can again be read as consent:\n" + "\n".join(offenders)
    )


def test_the_settings_file_no_longer_interpolates_the_profile() -> None:
    """This defect class lives in YAML, so the guard has to reach YAML too."""
    text = (_ROOT / "config" / "settings.yaml").read_text(encoding="utf-8")
    interpolations = [
        line
        for line in text.splitlines()
        # Comments may name the variable (they explain why it is not here); declarations may not.
        if not line.lstrip().startswith("#")
        and (re.search(r"^\s*profile\s*:", line) or f"${{{PROFILE_ENV}" in line)
    ]
    assert not interpolations, (
        "config/settings.yaml declares the profile again; '${" + PROFILE_ENV + ":-local}' is a "
        "two-state read that cannot tell an unset variable from a chosen 'local':\n"
        + "\n".join(interpolations)
    )


def test_a_resurrected_profile_key_is_refused_rather_than_ignored() -> None:
    with pytest.raises(ProfileError, match="must not declare 'profile'"):
        Settings.from_dict({"profile": "local"})


# --------------------------------------------------------------------------- #
# Three states, and unset is not a member of the valid set
# --------------------------------------------------------------------------- #
def test_the_resolver_treats_an_ABSENT_variable_as_no_choice() -> None:
    choice = resolve_profile({})
    assert choice.explicit is False
    assert choice.service_auth_configured is False


def test_an_EMPTIED_variable_refuses_rather_than_landing_where_unset_lands() -> None:
    """An assertion that PINS the collapse the resolver's docstring describes as a feature

    Sharing the unset landing is fail-closed but indistinguishable, and a state nothing can
    tell apart is a state no guard can act on. An operator who deliberately emptied the
    variable expressed an intent that names no profile, so it refuses at import instead.
    """
    for environ in ({PROFILE_ENV: ""}, {PROFILE_ENV: "   "}):
        with pytest.raises(ConfiguredEmptyError):
            resolve_profile(environ)


def test_an_unconsented_run_is_not_the_local_profile_for_any_relaxation() -> None:
    choice = resolve_profile({})
    assert choice.exposure_profile == UNCONSENTED_PROFILE
    assert choice.exposure_profile != "local"
    assert UNCONSENTED_PROFILE not in RUNTIME_PROFILES


def test_an_unconsented_run_still_binds_loopback() -> None:
    """The exposure guard fails closed the OTHER way: local is the restrictive case."""
    assert resolve_profile({}).bind_profile == "local"


def test_a_deliberate_profile_is_carried_through_unchanged() -> None:
    for profile in sorted(RUNTIME_PROFILES):
        choice = resolve_profile({PROFILE_ENV: profile})
        assert (choice.profile, choice.explicit) == (profile, True)
        assert choice.exposure_profile == profile
        assert choice.bind_profile == profile
        assert choice.service_auth_configured is True


@pytest.mark.parametrize("value", _MIS_CAPITALISED)
def test_a_mis_capitalised_or_unknown_profile_is_refused_by_the_resolver(value: str) -> None:
    with pytest.raises(ProfileError, match="unknown OBSERVABILITY_PROFILE"):
        resolve_profile({PROFILE_ENV: value})


@pytest.mark.parametrize("value", _WHITESPACE_WRAPPED)
def test_surrounding_whitespace_resolves_to_the_profile_the_operator_meant(value: str) -> None:
    """The value the posture decisions judge is EXACTLY the value the resolver returns.

    A YAML interpolation that passes `' local'` through unstripped means a profile arriving
    with a trailing newline out of a config map matches no posture comparison and disables the
    exposure guard exactly the way `Local` does.
    """
    choice = resolve_profile({PROFILE_ENV: value})
    assert choice.profile == value.strip()
    assert choice.profile in RUNTIME_PROFILES
    assert choice.explicit is True
    assert choice.exposure_profile == value.strip()


@pytest.mark.parametrize("value", ("Local", "LOCAL", "bogus", "unconfigured"))
def test_settings_cannot_even_be_constructed_with_an_unbindable_profile(value: str) -> None:
    """Validation is on the Settings object, so no code path reaches an app with a typo."""
    with pytest.raises(ProfileError):
        Settings(profile=value, local=LocalSettings(audit_path=":memory:"))


# --------------------------------------------------------------------------- #
# Finding 1, at the HTTP layer: no profile chosen is no credential accepted
# --------------------------------------------------------------------------- #
def _client(*, explicit: bool, peer: tuple[str, int] = _LOOPBACK_PEER) -> TestClient:
    settings = Settings(
        profile="local",
        profile_explicit=explicit,
        local=LocalSettings(audit_path=":memory:"),
        adapters=_ADAPTER_BINDINGS,
    )
    return TestClient(create_app(settings), client=peer)


def test_an_unconsented_run_refuses_the_zero_secret_worm_ingest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unguarded ingest answers 202 ACCEPTED to an attacker-chosen actor, no bearer token."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    forged = sample_event(event_id="unconsented-forgery-1")
    forged["actor"] = "attacker@evil.example"
    response = _client(explicit=False).post("/v1/audit", json=forged)
    assert response.status_code == 503, (
        "an unconfigured run accepted a forged audit record; an unset "
        f"{PROFILE_ENV} is not consent to the zero-secret ingest"
    )
    assert _TOKEN_ENV in response.json()["detail"]


def test_a_deliberate_local_profile_keeps_the_zero_secret_offline_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opening the offline gate depends on is preserved EXACTLY, and only here."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    assert _client(explicit=True).post("/v1/audit", json=sample_event()).status_code == 202


def test_an_unconsented_run_stays_bound_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Closing the S2S opening must not LOOSEN the exposure guard for the same run."""
    monkeypatch.delenv(_TOKEN_ENV, raising=False)
    monkeypatch.delenv("OBSERVABILITY_ALLOW_INSECURE_DEMO", raising=False)
    assert _client(explicit=False, peer=_LAN_PEER).get("/healthz").status_code == 503


# --------------------------------------------------------------------------- #
# Finding 2, in a real interpreter: the typo is a BOOT failure
# --------------------------------------------------------------------------- #
_IMPORT_THE_SERVED_APP = (
    "import sys; sys.path.insert(0, 'src'); "
    "import observability.api.app as m; print('SERVING', m.app.title)"
)


def _boot(profile_value: str | None) -> subprocess.CompletedProcess[str]:
    """Import the module `uvicorn observability.api.app:app` imports, in a fresh process."""
    env = dict(os.environ)
    env.pop(PROFILE_ENV, None)
    env.pop(_TOKEN_ENV, None)
    env.pop("FIRESTORE_EMULATOR_HOST", None)
    env["OBSERVABILITY_LOCAL_AUDIT"] = ":memory:"
    if profile_value is not None:
        env[PROFILE_ENV] = profile_value
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _IMPORT_THE_SERVED_APP],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("value", _MIS_CAPITALISED)
def test_a_mis_capitalised_profile_fails_the_boot_of_the_shipped_entry_point(value: str) -> None:
    """Unvalidated, every one of these imports cleanly and then SERVES."""
    result = _boot(value)
    assert result.returncode != 0, (
        f"{PROFILE_ENV}={value!r} produced a serving app; the exposure guard compares "
        "== 'local', so the typo disabled it instead of tripping it"
    )
    assert "SERVING" not in result.stdout
    assert "unknown OBSERVABILITY_PROFILE" in result.stderr


@pytest.mark.parametrize("value", (None, "local", "gcp", "onprem", *_WHITESPACE_WRAPPED))
def test_a_valid_or_absent_profile_still_boots(value: str | None) -> None:
    """The refusal is of typos and of emptied values, not of the documented states.

    An UNSET variable still boots and serves (on loopback, granting nothing). ``""`` and
    ``"   "`` are deliberately NOT in this list: lumping them in here is what makes the emptied
    state untestable as its own thing. They have their own test below, asserting the boot FAILS.
    """
    result = _boot(value)
    assert result.returncode == 0, result.stderr
    assert "SERVING" in result.stdout


@pytest.mark.parametrize("value", ("", "   "))
def test_an_emptied_profile_refuses_to_boot(value: str) -> None:
    """An emptied variable kills the process before it serves, like an unknown one."""
    result = _boot(value)
    assert result.returncode != 0
    assert "SERVING" not in result.stdout
    assert PROFILE_ENV in result.stderr


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
