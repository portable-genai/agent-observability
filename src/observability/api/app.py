"""FastAPI application for Hrz5 Agent Observability, Audit & FinOps.

Endpoints (SPEC §6, Hrz5):

* ``POST /v1/audit``  — write one already-redacted ``AuditEvent`` to immutable WORM
  storage (locked Cloud Logging bucket on the ``gcp`` profile). Returns ``202 Accepted``.
* ``GET  /v1/audit``  — read back recent redacted events for demos / regulator pulls,
  filtered by ``actor`` / ``action`` and bounded by ``limit``.
* ``GET  /healthz``   — liveness.

OTLP trace ingest is **infra** (an OpenTelemetry collector; see ``infra/otel/``), not
part of this HTTP contract.

The app builds a :class:`Container` once at startup and reuses the bound
:class:`AuditSinkPort`. The active ``profile`` (``gcp`` | ``local`` | ``onprem``) decides
whether writes hit the locked Cloud Logging bucket, the SDK-free SQLite WORM stand-in, or
the fail-fast on-prem placeholder.

The profile is resolved ONCE, by :func:`observability.config.resolve_profile`, and an unset
``OBSERVABILITY_PROFILE`` is NOT consent to the ``local`` profile's zero-secret ingest: it
resolves to ``unconfigured`` for every relaxation and to ``local`` for every restriction.
Because ``Settings`` validates the profile in ``__post_init__`` and the module-level ``app``
below builds one at import, an unknown or mis-capitalised value fails the boot of
``uvicorn observability.api.app:app`` instead of producing a serving app whose exposure guard
compares ``== "local"``, does not match, and therefore never applies.

WHAT SWITCHES THE EXPOSURE GUARD OFF is one thing and one thing only: the caller-identity scheme
the active binding names declaring that it VERIFIES its caller (``ports/identity.py``, bound in
``api/security.py``). The guard bounds the WHOLE app, including ``/healthz`` and
``/v1/capabilities``, which carry no credential by design, so the question it has to settle is
whether this deployment can authenticate anybody at all. Deriving it from the profile string
plus the ABSENCE of ``OBSERVABILITY_S2S_TOKEN`` is wrong in the most dangerous direction: setting
a service credential switches the guard OFF, and a peer at another address on the LAN, holding
nothing, reads ``/healthz`` and the full capability manifest off a laptop demo. That same
expression also excludes the ``onprem`` profile entirely, which then answers the same two routes
to a LAN peer with no credential and no secret configured at all.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from hex_service_kit import AuditChainError, read_env_setting
from hex_service_kit.capabilities import (
    AssuranceLevel,
    Capability,
    CapabilityManifest,
    CapabilityMode,
)
from hex_service_kit.web import add_loopback_exposure_guard

from .. import __version__
from ..config import Settings
from ..container import Container
from ..errors import IdempotencyConflict
from ..ports.identity import VERIFIED, PortabilityPlaceholderError
from ..schemas import (
    AuditAccepted,
    AuditEventModel,
    CapabilityManifestModel,
    HealthResponse,
    ReleaseApprovalRequest,
)
from ..serialization import to_jsonable
from .security import ServiceCaller, caller_auth_kind, require_release_approver

# Max number of read-back events a single GET may return (demo guard).
_MAX_READ_LIMIT = 500

# The operator's explicit opt-in to serving the zero-secret local posture off loopback, the
# same shape as the bind guard's. Read per request by the middleware, never baked in here.
_INSECURE_DEMO_ENV = "OBSERVABILITY_ALLOW_INSECURE_DEMO"


def _is_unauthenticated_posture(settings: Settings) -> bool:
    """Is this app unfit to be served to anything but a loopback peer?

    It is, unless BOTH of these hold, and the guard bounds every case where either fails:

    1. a profile was chosen. Absent that, nobody selected an authentication scheme at all; the
       ingest already refuses every caller, but ``/healthz`` and ``/v1/capabilities`` would
       still answer a stranger, and a deployment nobody configured has no business being
       reachable. It is also the one case where a rebinding that named a verifying scheme under
       ``local`` must NOT buy the relaxation: unset is not consent, whatever the binding says;
    2. the caller-identity scheme the active binding names DECLARES that it VERIFIES its caller
       (``ports/identity.py``, bound in ``api/security.py``). The offline scheme compares a
       pre-shared string, which is symmetric, anonymous and simply absent when nobody configured
       one; the on-premises placeholder verifies nothing at all. Neither authenticates anybody,
       so neither may switch this off.

    Note what is NOT in this expression: ``OBSERVABILITY_S2S_TOKEN``. Whether a credential
    happens to be SET is not evidence that this deployment can authenticate its callers, and it
    is no evidence at all about ``/healthz`` and ``/v1/capabilities``, which carry no credential
    by design. While it was in here, setting the token switched the guard off and a LAN peer
    holding nothing read both of those routes off a laptop demo. The credential belongs where it
    already is: in the S2S dependency guarding the ingest, one route at a time.

    ``gcp`` binds the OIDC scheme, which verifies a Google-signed assertion against its issuer,
    expiry and audience and then matches the caller against an allowlist, so it stands the guard
    down: the platform fronts that deployment and every data route refuses an unverified caller
    on its own.
    """
    return not (settings.profile_explicit and caller_auth_kind(settings.profile) == VERIFIED)


def _integrity_unavailable(exc: AuditChainError) -> HTTPException:
    """503 when the WORM store refuses to append because it disagrees with its witness.

    The local store fails closed once its contents no longer match the external anchor:
    accepting the write would re-anchor a possibly tampered store and launder the
    divergence. That is an audit outage needing an operator (``audit verify``, then a
    deliberate ``audit reanchor --confirm`` only if the trail checks out against something
    the store could not write), not a client error to retry, hence 503 rather than 5xx noise
    or a silent 202.
    """
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            "audit store integrity check failed, writes refused (fail closed): "
            f"{exc}. Run 'agent-observability audit verify'."
        ),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    container = Container(settings)

    app = FastAPI(
        title="Hrz5 Agent Observability, Audit & FinOps",
        version=__version__,
        summary=(
            "WORM audit trail + OpenTelemetry tracing + token cost/latency FinOps for "
            "the Horizon agent platform."
        ),
        description=(
            "Catalog system **Hrz5** (group `hrz`). Mandatory platform dependency of the "
            "Rsk1 Compliance Assistant: Rsk1 routes every immutable audit record here via "
            "`POST /v1/audit` (rule **R2**, compliance-grade WORM). Backed by a *locked* "
            "Cloud Logging bucket (~7y retention), a log sink, and a BigQuery FinOps "
            "export in the configured GCP region. Prompts/responses arrive already redacted "
            "(rule **R1**)."
        ),
    )
    app.state.container = container
    app.state.settings = container.settings

    @app.exception_handler(PortabilityPlaceholderError)
    def _placeholder_called(request: Request, exc: PortabilityPlaceholderError) -> JSONResponse:
        """Answer a migration placeholder with its status and its reason, never a bare 500.

        A bare ``NotImplementedError`` is not something the framework knows how to answer, so
        it became ``500 Internal Server Error`` with no body. Executed before this handler
        existed: an AUTHENTICATED ``POST /v1/audit`` and ``GET /v1/audit`` under
        ``OBSERVABILITY_PROFILE=onprem`` both answered 500, telling the caller nothing and the
        operator nothing either. The placeholder now says which port is unbound and what to do.
        """
        return JSONResponse(status_code=exc.http_status, content={"detail": str(exc)})

    # Bound the zero-secret posture on the SERVING path, not in an entry point. The
    # Dockerfile CMD is `uvicorn observability.api.app:app --host 0.0.0.0`, so anything that
    # lived in a `main()` would never run in a shipped process: the WORM ingest would take a
    # forged audit record from any LAN peer with no bearer token. The guard rides the app
    # object instead, so it holds however the app is served.
    add_loopback_exposure_guard(
        app,
        unauthenticated=_is_unauthenticated_posture(container.settings),
        insecure_demo_env=_INSECURE_DEMO_ENV,
        # The EXPOSURE profile, so a run nobody configured names itself 'unconfigured' in the
        # refusal rather than borrowing the name of a profile an operator never chose.
        posture=container.settings.exposure_profile,
    )

    @app.get("/healthz", response_model=HealthResponse, tags=["ops"])
    def healthz() -> HealthResponse:
        manifest = _capability_manifest(container.settings)
        return HealthResponse(
            status="ok",
            profile=manifest.profile,
            region=manifest.region,
            demo_only=manifest.demo_only,
            production_ready=manifest.production_ready,
        )

    @app.get("/v1/capabilities", response_model=CapabilityManifestModel, tags=["ops"])
    def capabilities() -> CapabilityManifestModel:
        return _capability_manifest(container.settings)

    @app.post(
        "/v1/audit",
        response_model=AuditAccepted,
        status_code=202,
        tags=["audit"],
        dependencies=[ServiceCaller],
    )
    def write_audit(
        event: AuditEventModel,
        idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    ) -> AuditAccepted:
        """Append one already-redacted ``AuditEvent`` to immutable WORM storage."""
        if event.action == "release-approved":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="release approvals require the reviewer-only endpoint",
            )
        key = (idempotency_key or "").strip()
        event_id = event.event_id.strip()
        if key and not event_id:
            event_id = "audit-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        if not event_id:
            event_id = f"audit-{uuid4().hex}"
        if not key:
            key = f"event:{event_id}"

        domain = replace(event.to_domain(), event_id=event_id)
        digest_body = to_jsonable(domain)
        if "timestamp" not in event.model_fields_set:
            digest_body.pop("timestamp", None)
        encoded = json.dumps(digest_body, sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        try:
            persisted_id = container.audit.record_once(
                domain,
                idempotency_key=key,
                payload_digest=digest,
            )
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except AuditChainError as exc:
            raise _integrity_unavailable(exc) from exc
        return AuditAccepted(event_id=persisted_id)

    @app.post(
        "/v1/release-approvals",
        response_model=AuditAccepted,
        status_code=202,
        tags=["governance"],
    )
    def write_release_approval(
        request: ReleaseApprovalRequest,
        reviewer: Annotated[str, Depends(require_release_approver)],
    ) -> AuditAccepted:
        """Persist a maker-checker approval stamped from verified reviewer identity."""
        key = (
            f"release:{request.agent_name}:{request.agent_version}:"
            f"{request.eval_run_id}:{request.approval_policy_version}"
        )
        event_id = "audit-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        domain = AuditEventModel(
            action="release-approved",
            actor=reviewer,
            decision="allowed",
            redacted_prompt="release approval",
            redacted_response="approved",
            resource=request.agent_name,
            run_id=request.eval_run_id,
            event_id=event_id,
            metadata={
                "agent_name": request.agent_name,
                "agent_version": request.agent_version,
                "eval_run_id": request.eval_run_id,
                "approval_policy_version": request.approval_policy_version,
            },
        ).to_domain()
        digest_body = to_jsonable(domain)
        digest_body.pop("timestamp", None)
        encoded = json.dumps(digest_body, sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        try:
            persisted_id = container.audit.record_once(
                domain,
                idempotency_key=key,
                payload_digest=digest,
            )
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except AuditChainError as exc:
            raise _integrity_unavailable(exc) from exc
        return AuditAccepted(event_id=persisted_id)

    @app.get(
        "/v1/audit/{event_id}",
        response_model=AuditEventModel,
        tags=["audit"],
        dependencies=[ServiceCaller],
    )
    def get_audit(event_id: str) -> AuditEventModel:
        """Resolve one immutable event for release and regulator evidence linkage."""
        event = container.audit.get(event_id)
        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="audit event not found",
            )
        return AuditEventModel.from_domain(event)

    @app.get(
        "/v1/audit",
        response_model=list[AuditEventModel],
        tags=["audit"],
        dependencies=[ServiceCaller],
    )
    def read_audit(
        actor: Annotated[str | None, Query(description="Filter by actor identity.")] = None,
        action: Annotated[str | None, Query(description="Filter by action.")] = None,
        limit: Annotated[
            int, Query(ge=1, le=_MAX_READ_LIMIT, description="Max events to return.")
        ] = 50,
    ) -> list[AuditEventModel]:
        """Read back recent redacted events (newest first) for demos / regulator pulls."""
        events = container.audit.read_recent(actor=actor, action=action, limit=limit)
        return [AuditEventModel.from_domain(e) for e in events]

    return app


def _capability(
    *,
    name: str,
    available: bool,
    mode: str,
    assurance: str,
    provider: str = "",
    reason: str = "",
    required_for_production: bool = False,
) -> Capability:
    """Build a kit :class:`Capability` from this service, VALIDATING both vocabularies.

    The enum constructors are the point rather than a formality: a mode or an assurance level
    this fleet does not define now raises here, instead of being served as a string that reads
    like it means something. The strings themselves are unchanged on the wire.
    """
    return Capability(
        name=name,
        available=available,
        mode=CapabilityMode(mode),
        assurance=AssuranceLevel(assurance),
        provider=provider,
        reason=reason,
        required_for_production=required_for_production,
    )


def _capability_manifest(settings: Settings) -> CapabilityManifestModel:
    # Every read below goes through the commons three-state reader, and every one of them
    # collapses UNSET and SET-AND-EMPTY deliberately: an attestation reference nobody set and
    # one an operator emptied are the same claim, which is "no attestation", and that is the
    # closed direction. The S2S pair is the one that matters most: an emptied audience or an
    # emptied caller allowlist leaves ``s2s_ready`` False rather than announcing readiness.
    demo_only = settings.profile == "local"
    managed = settings.profile == "gcp"
    refs = {
        "audit-api": read_env_setting("OBSERVABILITY_AUDIT_ATTESTATION_REF").value,
        "locked-worm": read_env_setting("OBSERVABILITY_WORM_ATTESTATION_REF").value,
        "otel-traces": read_env_setting("OBSERVABILITY_OTEL_ATTESTATION_REF").value,
        "finops-export": read_env_setting("OBSERVABILITY_FINOPS_ATTESTATION_REF").value,
        "slo-alerting": read_env_setting("OBSERVABILITY_SLO_ATTESTATION_REF").value,
    }
    s2s_ready = bool(
        read_env_setting("OBSERVABILITY_S2S_AUDIENCE").value
        and read_env_setting("OBSERVABILITY_S2S_ALLOWED_CALLERS").value
    )

    def assurance(name: str) -> str:
        return "attested" if managed and refs[name] else "not-attested"

    items = [
        _capability(
            name="audit-api",
            available=demo_only or (managed and s2s_ready),
            mode="local" if demo_only else ("managed" if managed else "disabled"),
            assurance="demo-only"
            if demo_only
            else (assurance("audit-api") if managed and s2s_ready else "unavailable"),
            provider="SQLite" if demo_only else "Cloud Logging",
            reason=(
                "functional append-only demo store; not a locked managed WORM bucket"
                if demo_only
                else (
                    ""
                    if managed and s2s_ready and refs["audit-api"]
                    else "service identity or audit attestation is not configured"
                )
            ),
            required_for_production=True,
        ),
        *[
            _capability(
                name=name,
                available=managed and configured,
                mode="managed" if managed else "disabled",
                assurance=assurance(name) if managed and configured else "unavailable",
                provider=provider,
                reason=(
                    "managed service intentionally absent from the laptop profile"
                    if demo_only
                    else (
                        ""
                        if managed and configured and refs[name]
                        else "runtime configuration or capability-specific attestation is missing"
                    )
                ),
                required_for_production=True,
            )
            for name, provider, configured in (
                ("locked-worm", "Cloud Logging locked bucket", bool(settings.logging.bucket_id)),
                (
                    "otel-traces",
                    "OpenTelemetry / Cloud Trace",
                    bool(read_env_setting("OBSERVABILITY_OTLP_ENDPOINT").value),
                ),
                (
                    "finops-export",
                    "BigQuery / Cloud Monitoring",
                    bool(settings.finops.bigquery_dataset and settings.finops.bigquery_table),
                ),
                (
                    "slo-alerting",
                    "Cloud Monitoring alert policies",
                    bool(read_env_setting("OBSERVABILITY_ALERT_CHANNELS").value),
                ),
            )
        ],
    ]
    # production_ready is NOT recomputed here: the kit manifest derives it from the
    # very capabilities just built, so the served flag and the rule behind it cannot
    # disagree. It used to be written out a second time, right above this line.
    return CapabilityManifestModel.from_manifest(
        CapabilityManifest(
            service="agent-observability",
            profile=settings.profile,
            region=settings.region,
            capabilities=tuple(items),
            demo_only=demo_only,
        )
    )


# Module-level app for ``uvicorn observability.api.app:app``.
app = create_app()
