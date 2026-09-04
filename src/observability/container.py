"""Dependency container for agent-observability.

Resolves the active ``profile`` to a concrete adapter instance by importing the dotted
path declared in ``config/settings.yaml`` under ``adapters:`` and constructing it with
the single :class:`Settings` argument. The ``local`` binding lets the service run with
no Google Cloud SDKs installed (the dev / test default); ``onprem`` is the fail-fast
migration target; ``gcp`` is the managed compliance store.
"""

from __future__ import annotations

import importlib
from functools import cached_property

from .config import Settings
from .ports import AuditSinkPort


def _load(dotted: str, settings: Settings) -> object:
    """Import ``module:Class`` and construct it with ``settings``."""
    module_path, _, class_name = dotted.partition(":")
    if not class_name:
        raise ValueError(f"adapter binding must be 'module:Class', got {dotted!r}")
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls(settings)


class Container:
    """Builds and caches the port implementation for the active profile."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()

    def _binding(self, port: str) -> str:
        bindings = self.settings.adapters.get(port, {})
        profile = self.settings.profile
        if profile in bindings:
            return bindings[profile]
        raise KeyError(f"no adapter bound for port {port!r} (profile {profile!r})")

    @cached_property
    def audit(self) -> AuditSinkPort:
        adapter = _load(self._binding("audit"), self.settings)
        assert isinstance(adapter, AuditSinkPort)  # runtime Protocol check
        return adapter
