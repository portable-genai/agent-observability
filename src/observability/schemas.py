"""Pydantic request/response schemas — the wire contract.

Mirrors SPEC §6 for **Hrz5 ``agent-observability``** field-for-field. The
``AuditEventModel`` body is exactly Rsk1's ``to_jsonable(AuditEvent)`` output, so Rsk1's
remote audit client serialises and this service deserialises without translation:

    POST /v1/audit  {AuditEvent}                       -> 202 Accepted (no body echo needed)
    GET  /v1/audit?actor=&action=&limit=               -> [ {AuditEvent}, ... ] (redacted)
    GET  /healthz                                       -> { "status": "ok" }

``AuditEvent`` JSON (SPEC §6):
    { "action","actor","decision","redacted_prompt","redacted_response",
      "citations":[{...Citation}],"resource","trace_id","timestamp","metadata":{} }

``Citation`` JSON mirrors the Rsk1 ``Citation`` dataclass:
    { "source_id","regulator","jurisdiction","title","url","version","page",
      "snippet","score" }

All enums serialise to their string ``.value``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .models import AuditEvent, Citation, Decision, utcnow

# --------------------------------------------------------------------------- #
# Shared models (used for both request and read-back response)
# --------------------------------------------------------------------------- #


class CitationModel(BaseModel):
    """Provenance attached to a claim — verbatim from Rsk1's ``Citation``."""

    model_config = ConfigDict(extra="ignore")

    source_id: str = ""
    regulator: str = ""
    jurisdiction: str = ""
    title: str = ""
    url: str = ""
    version: str = "unknown"
    page: int | None = None
    snippet: str = ""
    score: float | None = None

    def to_domain(self) -> Citation:
        return Citation(
            source_id=self.source_id,
            regulator=self.regulator,
            jurisdiction=self.jurisdiction,
            title=self.title,
            url=self.url,
            version=self.version,
            page=self.page,
            snippet=self.snippet,
            score=self.score,
        )

    @classmethod
    def from_domain(cls, citation: Citation) -> CitationModel:
        return cls(
            source_id=citation.source_id,
            regulator=citation.regulator,
            jurisdiction=citation.jurisdiction,
            title=citation.title,
            url=citation.url,
            version=citation.version,
            page=citation.page,
            snippet=citation.snippet,
            score=citation.score,
        )


class AuditEventModel(BaseModel):
    """The ``AuditEvent`` wire contract (SPEC §6, Hrz5).

    ``decision`` is the enum string (``"allowed"`` | ``"blocked"`` | ``"escalated"``).
    ``timestamp`` is ISO 8601; it defaults to *now* if a client omits it. Unknown extra
    keys are ignored so the contract tolerates additive, backward-compatible changes.
    """

    model_config = ConfigDict(extra="ignore")

    action: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    decision: Literal["allowed", "blocked", "escalated"]
    redacted_prompt: str = ""
    redacted_response: str = ""
    citations: list[CitationModel] = Field(default_factory=list)
    resource: str = "compliance-advisory"
    trace_id: str | None = None
    span_id: str | None = None
    correlation_id: str | None = None
    run_id: str | None = None
    event_id: str = ""
    schema_version: Literal["audit-event/v2"] = "audit-event/v2"
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def upgrade_v1_payload(cls, value: object) -> object:
        """Accept the old Hrz4 ``summary/detail`` names without losing evidence."""
        if not isinstance(value, dict):
            return value
        upgraded = dict(value)
        if "redacted_prompt" not in upgraded and "summary" in upgraded:
            upgraded["redacted_prompt"] = upgraded["summary"]
        if "redacted_response" not in upgraded and "detail" in upgraded:
            upgraded["redacted_response"] = upgraded["detail"]
        return upgraded

    def to_domain(self) -> AuditEvent:
        return AuditEvent(
            action=self.action,
            actor=self.actor,
            decision=Decision(self.decision),
            redacted_prompt=self.redacted_prompt,
            redacted_response=self.redacted_response,
            citations=tuple(c.to_domain() for c in self.citations),
            resource=self.resource,
            trace_id=self.trace_id,
            span_id=self.span_id,
            correlation_id=self.correlation_id,
            run_id=self.run_id,
            event_id=self.event_id,
            schema_version=self.schema_version,
            timestamp=self.timestamp,
            metadata=dict(self.metadata),
        )

    @classmethod
    def from_domain(cls, event: AuditEvent) -> AuditEventModel:
        if event.schema_version != "audit-event/v2":
            raise ValueError(f"unsupported audit event schema {event.schema_version!r}")
        return cls(
            action=event.action,
            actor=event.actor,
            decision=event.decision.value,
            redacted_prompt=event.redacted_prompt,
            redacted_response=event.redacted_response,
            citations=[CitationModel.from_domain(c) for c in event.citations],
            resource=event.resource,
            trace_id=event.trace_id,
            span_id=event.span_id,
            correlation_id=event.correlation_id,
            run_id=event.run_id,
            event_id=event.event_id,
            schema_version="audit-event/v2",
            timestamp=event.timestamp,
            metadata=dict(event.metadata),
        )


class AuditAccepted(BaseModel):
    """Body returned with ``202 Accepted`` from ``POST /v1/audit``."""

    status: Literal["accepted"] = "accepted"
    event_id: str = Field(min_length=1)


class ReleaseApprovalRequest(BaseModel):
    """Reviewer-controlled facts; identity, action, and decision are server-stamped."""

    agent_name: str = Field(min_length=1)
    agent_version: str = Field(min_length=1)
    eval_run_id: str = Field(min_length=1)
    approval_policy_version: str = Field(min_length=1)


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    profile: str = "local"
    region: str = "asia-southeast1"
    demo_only: bool = True
    production_ready: bool = False


class CapabilityModel(BaseModel):
    name: str
    available: bool
    mode: str
    assurance: str
    provider: str = ""
    reason: str = ""
    required_for_production: bool = False


class CapabilityManifestModel(BaseModel):
    service: str
    profile: str
    region: str
    capabilities: list[CapabilityModel]
    schema_version: str = "capability-manifest/v1"
    portable_core: bool = True
    demo_only: bool = False
    production_ready: bool = False
