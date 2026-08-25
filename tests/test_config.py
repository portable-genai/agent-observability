"""How ``config/settings.yaml`` is FOUND, and what happens when it is not.

Kept apart from the settings-content tests on purpose: everything here is about the loader's
own failure modes, which is the layer that broke in the managed deployment while every
content test stayed green.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from observability import config as config_module
from observability.config import CONFIG_PATH_ENV, Settings, SettingsNotFound


def test_a_missing_settings_file_is_refused_rather_than_defaulted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The packaging defect that took the deployed service down, as a test.

    ``load()`` used to treat an absent file as an empty mapping. ``from_dict`` then supplied
    defaults for everything EXCEPT ``adapters:``, which has no default, so the container bound
    no ports at all. Nothing failed at boot: ``/healthz`` touches no port and answered 200 for
    as long as the service ran, and the first real request died on ``no adapter bound for port
    'audit' (profile 'gcp')`` -- a message that points at the adapter layer rather than at the
    configuration file that was never read.

    That is exactly what happened in the managed deployment. ``parents[2]`` resolves to the
    repository root from ``src/observability/config.py`` and to ``site-packages/../..`` from the
    installed wheel, so the file was found in development and in no built image.
    """

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(CONFIG_PATH_ENV, raising=False)
    monkeypatch.setattr(config_module, "_SETTINGS_SEARCH_PATH", (tmp_path / "config" / "x.yaml",))
    with pytest.raises(SettingsNotFound):
        Settings.load()


def test_an_explicitly_named_settings_file_is_used(tmp_path: Path) -> None:
    named = tmp_path / "named.yaml"
    named.write_text(
        "project_id: p\nregion: us-central1\nallowed_regions: [us-central1]\n"
        "adapters:\n  audit:\n    local: observability.adapters.local.audit:"
        "LocalAppendOnlyAuditAdapter\n",
        encoding="utf-8",
    )
    assert Settings.load(named).adapters["audit"]["local"].endswith("LocalAppendOnlyAuditAdapter")


def test_a_named_settings_file_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SettingsNotFound):
        Settings.load(tmp_path / "absent.yaml")


def test_the_config_path_variable_is_read_in_three_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(CONFIG_PATH_ENV, "")
    with pytest.raises(SettingsNotFound):
        Settings.load()
    monkeypatch.setenv(CONFIG_PATH_ENV, str(tmp_path / "nope.yaml"))
    with pytest.raises(SettingsNotFound):
        Settings.load()


def test_the_working_directory_is_searched_so_a_built_image_finds_its_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image copies `config/` next to the process, not next to the installed package."""

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yaml").write_text(
        "project_id: p\nregion: us-central1\nallowed_regions: [us-central1]\n"
        "adapters:\n  audit:\n    gcp: observability.adapters.gcp.cloud_logging_audit:"
        "CloudLoggingAuditAdapter\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(CONFIG_PATH_ENV, raising=False)
    assert "gcp" in Settings.load().adapters["audit"]
