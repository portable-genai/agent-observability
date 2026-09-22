"""The audit sink asks for the Firestore database the stack creates, and for no other.

Until 2026-09-22 the gcp sink named its idempotency database with a literal, the retired
``hrz-observability-idempotency``. The catalog-id rename changed ``infra/terraform/firestore.tf``
to ``agent-observability-idempotency`` and missed the literal, so after the stack was applied
whole on 2026-09-14 the deployed sink asked for a database that no longer existed. Every audit
write then failed with ``404 The database ... does not exist``, and because journey-portal
refuses to proxy a request it cannot audit, every embedded app behind the deployed portal
answered ``503 portal access audit is unavailable`` for eight days.

No test could see it. The one idempotency test injected a ready-made Firestore client, which
skips exactly the line that was wrong: the construction that names the database. So this file
constructs it, and holds the three places the name lives -- the Terraform resource, the env the
stack passes, and the settings default -- to one value.
"""

from __future__ import annotations

import ast
import re
import sys
import types
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from observability.adapters.gcp.cloud_logging_audit import CloudLoggingAuditAdapter
from observability.config import IDEMPOTENCY_DATABASE, LoggingSettings, Settings

_ROOT = Path(__file__).resolve().parents[1]
_TERRAFORM = _ROOT / "infra" / "terraform"


def _terraform_database_name() -> str:
    source = (_TERRAFORM / "firestore.tf").read_text(encoding="utf-8")
    block = re.search(
        r'resource\s+"google_firestore_database"\s+"audit_idempotency"\s*\{(.*?)\n\}',
        source,
        re.DOTALL,
    )
    assert block is not None, "firestore.tf no longer declares audit_idempotency"
    name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block.group(1), re.MULTILINE)
    assert name is not None, "audit_idempotency declares no literal name"
    return name.group(1)


def test_the_default_is_the_database_terraform_creates() -> None:
    assert _terraform_database_name() == IDEMPOTENCY_DATABASE
    assert LoggingSettings().idempotency_database == IDEMPOTENCY_DATABASE


def test_the_shipped_settings_file_resolves_to_the_same_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OBSERVABILITY_IDEMPOTENCY_DATABASE", raising=False)
    monkeypatch.setenv("OBSERVABILITY_PROFILE", "local")

    loaded = Settings.load(_ROOT / "config" / "settings.yaml")

    assert loaded.logging.idempotency_database == _terraform_database_name()


def test_the_deployment_passes_the_name_from_the_resource_itself() -> None:
    """Not a second literal: the env value IS the resource's name attribute."""
    source = (_TERRAFORM / "cloud_run.tf").read_text(encoding="utf-8")
    env = re.search(
        r'env\s*\{\s*name\s*=\s*"OBSERVABILITY_IDEMPOTENCY_DATABASE"\s*'
        r"value\s*=\s*([^\n]+)\n",
        source,
    )
    assert env is not None, "cloud_run.tf passes no OBSERVABILITY_IDEMPOTENCY_DATABASE"
    assert env.group(1).strip() == "google_firestore_database.audit_idempotency.name"


class _FakeFirestoreClient:
    constructed: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        type(self).constructed.append(kwargs)

    def collection(self, name: str) -> Any:
        raise AssertionError("construction is what is under test; nothing is written")


@pytest.fixture()
def fake_firestore(monkeypatch: pytest.MonkeyPatch) -> type[_FakeFirestoreClient]:
    """Stand in for ``google.cloud.firestore`` so the lazy import resolves offline."""
    _FakeFirestoreClient.constructed = []
    module = types.ModuleType("google.cloud.firestore")
    module.Client = _FakeFirestoreClient  # type: ignore[attr-defined]
    cloud = sys.modules.get("google.cloud") or types.ModuleType("google.cloud")
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", module)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setattr(cloud, "firestore", module, raising=False)
    if "google" not in sys.modules:
        google = types.ModuleType("google")
        monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setattr(sys.modules["google"], "cloud", cloud, raising=False)
    return _FakeFirestoreClient


def _reserve(settings: Settings) -> None:
    adapter = CloudLoggingAuditAdapter(settings)
    with pytest.raises(AssertionError, match="construction is what is under test"):
        adapter._reserve_idempotency_key("idempotency:k", "event-1", "sha256:d")


def test_the_sink_constructs_its_client_against_the_configured_database(
    settings: Settings, fake_firestore: type[_FakeFirestoreClient]
) -> None:
    configured = replace(
        settings,
        logging=replace(settings.logging, idempotency_database="named-by-the-stack"),
    )

    _reserve(configured)

    assert fake_firestore.constructed == [
        {"project": "test-project", "database": "named-by-the-stack"}
    ]


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_database_name_is_refused_rather_than_taken_as_default(
    settings: Settings, fake_firestore: type[_FakeFirestoreClient], empty: str
) -> None:
    """The client reads an empty name as "(default)": a ledger in an unprovisioned database."""
    configured = replace(settings, logging=replace(settings.logging, idempotency_database=empty))
    adapter = CloudLoggingAuditAdapter(configured)

    with pytest.raises(ValueError, match="idempotency_database is empty"):
        adapter._reserve_idempotency_key("idempotency:k", "event-1", "sha256:d")
    assert fake_firestore.constructed == []


def test_no_source_file_names_a_database_with_a_literal() -> None:
    """The regression guard: a ``database=`` keyword may never be handed a string constant."""
    offenders = []
    for path in sorted((_ROOT / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                value = keyword.value
                if (
                    keyword.arg == "database"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    offenders.append(f"{path.relative_to(_ROOT)}:{node.lineno}")
    assert offenders == []
