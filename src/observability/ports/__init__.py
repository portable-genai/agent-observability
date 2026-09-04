"""Ports — the interfaces agent-observability adapters implement.

``identity`` is the odd one out and deliberately so: it declares no Protocol, because
agent-observability binds no identity ADAPTER. It holds what a caller-identity SCHEME declares about
the authentication it provides, which is what the loopback exposure guard is derived from, plus the
refusal a portability placeholder raises on a serving path.
"""

from __future__ import annotations

from .audit import AuditSinkPort
from .identity import (
    CALLER_AUTH_ATTR,
    CALLER_AUTH_KINDS,
    PRESHARED,
    UNIMPLEMENTED,
    VERIFIED,
    PortabilityPlaceholderError,
    declared_caller_auth,
)

__all__ = [
    "CALLER_AUTH_ATTR",
    "CALLER_AUTH_KINDS",
    "PRESHARED",
    "UNIMPLEMENTED",
    "VERIFIED",
    "AuditSinkPort",
    "PortabilityPlaceholderError",
    "declared_caller_auth",
]
