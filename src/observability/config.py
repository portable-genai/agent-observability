"""Runtime configuration for Hrz5 Observability, Audit & FinOps.

A single :class:`Settings` object is loaded from ``config/settings.yaml`` with
``${ENV:-default}`` interpolation, then handed to every adapter constructor
(``def __init__(self, settings: Settings) -> None``). The ``profile`` selects which
adapter family the :class:`~observability.container.Container` binds:

* ``gcp``    - Cloud Logging *locked bucket* WORM adapter (real SDK calls).
* ``local``  - SDK-free, deterministic, append-only SQLite WORM stand-in (default for
  dev / test). Runs the whole service offline with no Google Cloud SDK, no API key, and
  no emulators. An optional Firestore-emulator branch is opt-in (see ``adapters/local``).
* ``onprem`` - fail-fast Google Distributed Cloud migration placeholder: constructs
  cleanly and satisfies the Protocol, but every method raises ``NotImplementedError``.

The GCP region is configurable and defaults to ``us-central1``.

**Two security-relevant settings are resolved here and NOWHERE else**, because
``${VAR:-default}`` interpolation is a TWO-state read (it cannot tell a variable nobody set
from one an operator deliberately set to empty) and both of these need three:

* ``OBSERVABILITY_PROFILE`` via :func:`resolve_profile`. Unset is not a member of
  :data:`RUNTIME_PROFILES`: it means NO CHOICE WAS MADE, which is never consent to the
  ``local`` profile's zero-secret WORM ingest. A value that IS present is validated at
  import, so an unknown or mis-capitalised profile is a boot failure rather than a serving
  app whose exposure guard silently does not apply.
* ``OBSERVABILITY_ALLOWED_REGIONS`` via :func:`resolve_allowed_regions`. An allowlist an
  operator set to an empty value names no approved region, so it refuses; it must never
  inherit the built-in default the way ``parsed or default`` used to make it.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from hex_service_kit import ConfiguredEmptyError, EnvSetting, read_env_setting

from .envread import setting_or_default

REGION = "us-central1"

#: The ONE environment variable naming the adapter family, read ONLY by
#: :func:`resolve_profile`. ``tests/test_profile_single_source.py`` fails the build if any
#: other module reads it, because a second read is a second chance to default permissively.
PROFILE_ENV = "OBSERVABILITY_PROFILE"
#: The residency allowlist variable, read ONLY by :func:`resolve_allowed_regions`.
ALLOWED_REGIONS_ENV = "OBSERVABILITY_ALLOWED_REGIONS"

#: Every profile this service binds an adapter family for. The comparison against it is
#: exact and case-sensitive: see :func:`_validate_profile`.
RUNTIME_PROFILES = frozenset({"gcp", "local", "onprem"})

#: The profile string handed to every EXPOSURE decision when ``OBSERVABILITY_PROFILE`` was
#: never set. It is deliberately NOT a member of :data:`RUNTIME_PROFILES` and never selects an
#: adapter: it exists so that "no choice was made" is a distinct input to the security layers
#: rather than being indistinguishable from a chosen ``local``.
UNCONSENTED_PROFILE = "unconfigured"
# Residency allowlist default (practice D5 / principle P-03). The SAME list Terraform
# validates `var.region` against, enforced a second time here so a deploy that bypassed
# Terraform (a hand-set GCP_REGION on a running service) still fails closed at app load
# instead of quietly writing the audit trail into an unapproved region.
ALLOWED_REGIONS: tuple[str, ...] = ("us-central1",)


class ResidencyError(ValueError):
    """The configured region is not in the deployment's residency allowlist."""


class ProfileError(ValueError):
    """The configured profile is not one this service binds an adapter family for."""


#: Where ``config/settings.yaml`` is looked for, in order, when no explicit path is given.
#:
#: ``parents[2]`` alone was correct for an EDITABLE install and wrong for every built image.
#: From ``src/observability/config.py`` it resolves to the repository root; from the wheel this
#: image actually installs, ``site-packages/observability/config.py``, it resolves to
#: ``site-packages/../../config/settings.yaml``, which exists nowhere. The Dockerfile does copy
#: the file, to ``/app/config``, and the process runs there, so the working directory finds it.
CONFIG_PATH_ENV = "OBSERVABILITY_CONFIG"
_SETTINGS_RELATIVE = Path("config") / "settings.yaml"
_SETTINGS_SEARCH_PATH = (
    Path.cwd() / _SETTINGS_RELATIVE,
    Path(__file__).resolve().parents[2] / _SETTINGS_RELATIVE,
)


class SettingsNotFound(RuntimeError):
    """No ``settings.yaml`` was found, and defaults are not a safe substitute for one.

    The loader used to shrug: a missing file produced an EMPTY mapping, ``from_dict`` filled in
    defaults, and the service booted with no ``adapters:`` block at all. ``/healthz`` answered
    200 the whole time, because health does not touch a port. The first real request died on
    ``no adapter bound for port 'audit'``, which reads like a packaging mistake in the adapter
    layer rather than what it was: the configuration file never being read.
    """


def _resolve_settings_path(path: str | os.PathLike[str] | None) -> Path:
    if path is not None:
        candidate = Path(path)
        if not candidate.exists():
            raise SettingsNotFound(f"settings file does not exist: {candidate}")
        return candidate
    # Three states, as everywhere else here: unset falls through to the search path, but SET
    # AND EMPTY is an operator naming no file and must not be read as "use the default".
    configured = read_env_setting(CONFIG_PATH_ENV)
    if configured.is_configured_empty:
        raise SettingsNotFound(
            f"{CONFIG_PATH_ENV} is set to an empty value, which names no file. Unset it to take "
            "the search path, or name the settings file you mean."
        )
    if not configured.is_unset:
        candidate = Path(configured.value)
        if not candidate.exists():
            raise SettingsNotFound(
                f"{CONFIG_PATH_ENV} names {candidate}, which does not exist. An operator who "
                "points this at the wrong path should be told, not silently given defaults."
            )
        return candidate
    for candidate in _SETTINGS_SEARCH_PATH:
        if candidate.exists():
            return candidate
    searched = ", ".join(str(candidate) for candidate in _SETTINGS_SEARCH_PATH)
    raise SettingsNotFound(
        "no config/settings.yaml was found. Without it there are no adapter bindings, so every "
        "port is unbound and the service can answer /healthz while being unable to serve one "
        f"real request. Searched: {searched}. Set {CONFIG_PATH_ENV} to name it explicitly."
    )


_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)(?::-([^}]*))?\}")


def _validate_profile(profile: str) -> str:
    """Fail closed on a profile string nothing binds, INCLUDING a capitalisation typo.

    The comparison is exact and case-sensitive on purpose: every posture decision downstream
    matches the profile string exactly, so ``Local`` selects none of the ``local`` relaxations
    but also none of the restrictions that the other profiles carry. Normalising the case here
    would turn a typo into a silent choice; refusing it turns the typo into a boot failure,
    which is the only outcome an operator will notice.
    """
    if profile not in RUNTIME_PROFILES:
        expected = ", ".join(sorted(RUNTIME_PROFILES))
        raise ProfileError(
            f"unknown {PROFILE_ENV} {profile!r}; expected exactly one of: {expected}. "
            "The comparison is case-sensitive: a mis-capitalised value selects none of the "
            "profile's relaxations and none of its restrictions, so it is refused here "
            "rather than served."
        )
    return profile


@dataclass(frozen=True, slots=True)
class ProfileChoice:
    """The ONE resolution of ``OBSERVABILITY_PROFILE``, and what each consumer keys off.

    Every module that needs the profile takes it from here (through :class:`Settings`) and
    never re-derives it with its own ``os.environ.get(PROFILE_ENV, "local")``: that fallback
    reads an UNSET variable as consent, which is the fail-open this type exists to remove.
    ``tests/test_profile_single_source.py`` fails the build if such a read reappears.

    The two derived profile strings differ because the two decisions fail closed in OPPOSITE
    directions, so a single "effective profile" would harden one and weaken the other.
    """

    #: Which adapter family to bind. Absent consent this is still ``local`` (the SDK-free
    #: adapters), because the alternative would import Google Cloud SDKs that are not
    #: installed. It grants nothing on its own: the WORM ingest refuses every caller when
    #: :attr:`explicit` is False, so an unconsented run has a store but no writer.
    profile: str = "local"
    #: Was the profile named DELIBERATELY (``OBSERVABILITY_PROFILE`` present and non-empty)?
    explicit: bool = True

    @property
    def exposure_profile(self) -> str:
        """The profile every RELAXATION keys off, starting with the zero-secret S2S opening.

        The shared-secret path opens for an unset token under exactly ``local``, so an
        unconsented run must NOT look like ``local``: it gets :data:`UNCONSENTED_PROFILE`,
        which matches no profile the commons opens for, so the ingest answers 503.
        """
        return self.profile if self.explicit else UNCONSENTED_PROFILE

    @property
    def bind_profile(self) -> str:
        """The profile the exposure guard keys off, where ``local`` is the RESTRICTIVE case.

        The loopback guard confines the unauthenticated ``local`` posture and lets fronted
        profiles serve a LAN peer, so here an unconsented run must look like ``local`` and
        stay bound to loopback.
        """
        return self.profile if self.explicit else "local"

    @property
    def service_auth_configured(self) -> bool:
        """May S2S callers be authenticated at all, or is the decision unconfigured?

        False means no profile was chosen, so neither S2S scheme has been selected and no
        request can be authenticated: the ingest refuses rather than letting the shared-secret
        path's loopback-dev opening apply.
        """
        return self.explicit


def _profile_setting(environ: Mapping[str, str] | None) -> EnvSetting:
    """``OBSERVABILITY_PROFILE`` in three states, from the real environment or an injected map.

    The injected form builds the SAME :class:`~hex_service_kit.EnvSetting` the commons would, so
    a test drives the identical three states rather than a second, kinder implementation of them.
    """
    if environ is None:
        return read_env_setting(PROFILE_ENV)
    raw = environ.get(PROFILE_ENV)
    return EnvSetting(name=PROFILE_ENV, raw=raw, value="" if raw is None else raw.strip())


def resolve_profile(environ: Mapping[str, str] | None = None) -> ProfileChoice:
    """Read ``OBSERVABILITY_PROFILE`` ONCE, treating absent/blank as NO CHOICE, not ``local``.

    Three states, because unset is not a member of :data:`RUNTIME_PROFILES`:

    * **unset** - no intent was expressed. The adapters still bind ``local`` (nothing else
      installs offline), but :attr:`ProfileChoice.explicit` is False, so every relaxation
      keyed off :attr:`ProfileChoice.exposure_profile` grants nothing.
    * **set and empty** - an intent WAS expressed and it names no profile, so it refuses at
      import with ``ConfiguredEmptyError`` rather than landing where unset lands. Sharing the
      unset landing made the two indistinguishable, and a state nothing can distinguish is a
      state no guard can act on.
    * **set and valid** - validated HERE, not later, so an unknown or mis-capitalised value
      is a boot failure. Validated nowhere at all, ``OBSERVABILITY_PROFILE=Local`` produces a
      serving app whose loopback exposure guard compares ``== "local"``, does not match, and
      therefore does not apply, so a LAN peer reaches a service that an unset or
      exactly-``local`` profile correctly refuses.
    """
    setting = _profile_setting(environ)
    if setting.is_configured_empty:
        raise ConfiguredEmptyError(
            f"{PROFILE_ENV} is set to an empty value, which is not a profile. Unset it to leave "
            f"the choice unmade, or set it to one of {', '.join(sorted(RUNTIME_PROFILES))}."
        )
    if setting.is_unset:
        return ProfileChoice(profile="local", explicit=False)
    _validate_profile(setting.value)
    return ProfileChoice(profile=setting.value, explicit=True)


def _interpolate(value: Any) -> Any:
    """Recursively expand ``${VAR:-default}`` placeholders, in THREE states rather than two.

    The settings loader's own expansion is a resolver, and ``os.environ.get(name, default)``
    reintroduces the two-state collapse one layer down, where no scan of adapter call sites
    would find it: a variable an operator deliberately emptied would take the default written in
    ``settings.yaml``. ``${VAR:-default}`` IS ``setting_or_default(VAR, default)`` written in
    YAML, so it delegates to that one implementation: UNSET takes the written default,
    SET-AND-EMPTY RAISES :class:`~hex_service_kit.netdefaults.ConfiguredEmptyError`,
    SET-AND-VALID wins. Resolving an emptied variable to empty instead would make
    ``${VAR:-http://audit:8080}`` indistinguishable from ``${VAR:-}``, and for a base URL, an
    allowlist or a path the empty string is the permissive branch.
    """
    if isinstance(value, str):

        def _sub(match: re.Match[str]) -> str:
            return setting_or_default(match.group(1), match.group(2) or "")

        return _ENV_PATTERN.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def _parse_regions(value: Any) -> tuple[str, ...]:
    """Parse a residency allowlist from a YAML list or a comma-separated string."""
    items = value.split(",") if isinstance(value, str) else list(value)
    return tuple(str(item).strip() for item in items if str(item).strip())


def resolve_allowed_regions(configured: Any = None) -> tuple[str, ...]:
    """Resolve the residency allowlist in THREE states, refusing an emptied one.

    ``configured`` is whatever ``config/settings.yaml`` declares, and
    ``OBSERVABILITY_ALLOWED_REGIONS`` overrides it. The variable is read here and nowhere
    else, because the old ``parsed or default`` laundered a deliberately emptied allowlist
    into the built-in one: an operator who set the variable and got an empty string (a
    templated ``.env`` line, a missing secret-manager substitution) silently deployed under
    the shipped single-region list rather than being told the list named nobody.

    * **unset** - the YAML declaration stands, or :data:`ALLOWED_REGIONS` when it declares
      none.
    * **set and empty**, including a value that names no region however it is punctuated
      (``","``) - :class:`ResidencyError`. An allowlist that admits no region is a
      configuration error, never "any region".
    * **set and valid** - the comma-separated regions, each stripped.
    """
    setting = read_env_setting(ALLOWED_REGIONS_ENV)
    if setting.has_value:
        parsed = _parse_regions(setting.value)
        if not parsed:
            raise ResidencyError(
                f"{ALLOWED_REGIONS_ENV} is set to {setting.value!r}, which names no "
                "residency-approved region. Unset it to take the shipped allowlist, or list "
                "the approved regions."
            )
        return parsed
    if setting.is_configured_empty:
        raise ResidencyError(
            f"{ALLOWED_REGIONS_ENV} is set to an empty value: an allowlist naming no region "
            "admits no deployment, and a variable that was deliberately set is not the same "
            "as an unset one. Unset it to take the shipped allowlist, or list the approved "
            "regions."
        )
    if configured is None:
        return ALLOWED_REGIONS
    return _parse_regions(configured) or ALLOWED_REGIONS


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class LoggingSettings:
    """Cloud Logging WORM-sink configuration.

    ``log_name`` is the structured log the audit events are written to; a Terraform sink
    routes that log into ``bucket_id`` (a *locked* Cloud Logging bucket, retention
    ``retention_days``). ``read_back_window`` is how many days of recent events
    ``GET /v1/audit`` reads for demos.
    """

    log_name: str = "agent-observability-audit"
    bucket_id: str = "agent-observability-worm"
    retention_days: int = 2557  # ~7 years (rule R2 WORM retention)
    read_back_window_days: int = 30


@dataclass(frozen=True, slots=True)
class FinOpsSettings:
    """BigQuery FinOps export configuration (token cost / latency dashboards)."""

    bigquery_dataset: str = "agent_finops"
    bigquery_table: str = "audit_events"


@dataclass(frozen=True, slots=True)
class LocalSettings:
    """Paths for the SDK-free ``local`` profile store (append-only SQLite WORM stand-in).

    An empty ``audit_path`` selects the per-package default under
    ``~/.observability/audit.db``; tests pass ``:memory:`` for an ephemeral, deterministic
    store. No Google Cloud here. The optional Firestore emulator (``FIRESTORE_EMULATOR_HOST``)
    is detected lazily inside the adapter, never imported on this default path.
    """

    audit_path: str = ""  # append-only audit store; "" => ~/.observability/audit.db
    # External chain-head anchor (practice C9). "" => derived as <audit_path>.anchor.json for
    # a file-backed store, and disabled for ``:memory:``. Point it at a different volume or a
    # path under different credentials than the store: an anchor an attacker can rewrite
    # alongside the store detects nothing.
    anchor_path: str = ""


@dataclass(frozen=True, slots=True)
class Settings:
    """Top-level configuration for the observability service."""

    project_id: str = "your-gcp-project"
    region: str = REGION
    # Residency allowlist (P-03). `region` is validated against it at load; an empty
    # allowlist is itself a configuration error, never "allow everything".
    allowed_regions: tuple[str, ...] = ALLOWED_REGIONS
    profile: str = "local"  # gcp | local | onprem
    # Local-store ring-buffer capacity (events retained for read-back demos).
    max_events: int = 1000
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    finops: FinOpsSettings = field(default_factory=FinOpsSettings)
    local: LocalSettings = field(default_factory=LocalSettings)
    adapters: dict[str, dict[str, str]] = field(default_factory=dict)
    # Was the profile chosen DELIBERATELY, or merely inherited because nobody set
    # OBSERVABILITY_PROFILE? `from_dict` sets this from `resolve_profile`. Constructing
    # Settings directly is deliberate by definition (a caller named the profile in code), so
    # the default is True; that is what keeps the offline test gate on its zero-secret
    # loopback demo while an unconfigured deployment gets nothing.
    profile_explicit: bool = True

    @property
    def exposure_profile(self) -> str:
        """The profile string every RELAXATION must key off (see :class:`ProfileChoice`)."""
        return self.profile if self.profile_explicit else UNCONSENTED_PROFILE

    @property
    def service_auth_configured(self) -> bool:
        """Has a profile been chosen, so that an S2S scheme has been selected at all?"""
        return self.profile_explicit

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Settings:
        cfg_path = _resolve_settings_path(path)
        loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        return cls.from_dict(_interpolate(loaded))

    def __post_init__(self) -> None:
        """Fail closed at load on an unbindable profile or an out-of-allowlist region.

        The profile check runs FIRST and raises, so ``OBSERVABILITY_PROFILE=Local`` cannot
        produce a Settings object at all. ``api/app.py`` builds one at module scope, which is
        what ``uvicorn observability.api.app:app`` imports, so the typo is a boot failure
        rather than an app serving with an exposure guard that silently does not match.
        """
        _validate_profile(self.profile)
        if not self.allowed_regions:
            raise ResidencyError(
                "allowed_regions must name at least one residency-approved region; "
                "an empty allowlist is a configuration error, not 'any region'"
            )
        if self.region not in self.allowed_regions:
            raise ResidencyError(
                f"region '{self.region}' is not in the residency allowlist "
                f"{list(self.allowed_regions)} (P-03). Set OBSERVABILITY_ALLOWED_REGIONS "
                "deliberately if this deployment is approved for it."
            )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Settings:
        """Build Settings from the parsed YAML, taking the profile from the environment ONLY.

        ``profile`` is deliberately NOT read from ``raw``. Reading it as
        ``${OBSERVABILITY_PROFILE:-local}`` is a two-state read: an unset variable arrives
        indistinguishable from a deliberately chosen ``local``, which is how the zero-secret
        WORM ingest comes to accept a forged record from a run nobody configured. A ``profile``
        key appearing in the YAML would silently restore that, so it is refused rather than
        ignored.
        """
        if "profile" in raw:
            raise ProfileError(
                "config/settings.yaml must not declare 'profile': the profile is resolved "
                f"only from {PROFILE_ENV}, in three states, by config.resolve_profile. A "
                "'${" + PROFILE_ENV + ":-local}' placeholder is a two-state read that makes "
                "an unset variable indistinguishable from a chosen 'local'."
            )
        choice = resolve_profile()
        log = raw.get("logging", {}) or {}
        fin = raw.get("finops", {}) or {}
        loc = raw.get("local", {}) or {}
        return cls(
            project_id=str(raw.get("project_id", "your-gcp-project")),
            region=str(raw.get("region", REGION)),
            allowed_regions=resolve_allowed_regions(raw.get("allowed_regions")),
            profile=choice.profile,
            profile_explicit=choice.explicit,
            max_events=_as_int(raw.get("max_events", 1000), 1000),
            logging=LoggingSettings(
                log_name=str(log.get("log_name", "agent-observability-audit")),
                bucket_id=str(log.get("bucket_id", "agent-observability-worm")),
                retention_days=_as_int(log.get("retention_days", 2557), 2557),
                read_back_window_days=_as_int(log.get("read_back_window_days", 30), 30),
            ),
            finops=FinOpsSettings(
                bigquery_dataset=str(fin.get("bigquery_dataset", "agent_finops")),
                bigquery_table=str(fin.get("bigquery_table", "audit_events")),
            ),
            local=LocalSettings(
                audit_path=str(loc.get("audit_path", "") or ""),
                anchor_path=str(loc.get("anchor_path", "") or ""),
            ),
            adapters=raw.get("adapters", {}) or {},
        )
