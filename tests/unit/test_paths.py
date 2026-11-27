"""Unit tests for Ether centralized path resolution."""

import os

from ether import paths
from ether.paths import (
    get_default_data_dir,
    get_default_db_path,
    get_default_exports_dir,
    get_default_logs_dir,
    get_default_reports_dir,
    get_default_scratchpad_path,
    get_default_settings_path,
)


def test_get_default_data_dir_env_override(tmp_path, monkeypatch):
    custom_dir = str(tmp_path / "custom_data_dir")
    monkeypatch.setenv("ETHER_DATA_DIR", custom_dir)
    resolved = get_default_data_dir()
    assert resolved == os.path.abspath(custom_dir)
    assert os.path.isdir(resolved)


def test_get_default_data_dir_default_path(monkeypatch):
    monkeypatch.delenv("ETHER_DATA_DIR", raising=False)
    resolved = get_default_data_dir()
    expected = os.path.abspath(os.path.expanduser("~/.ether"))
    assert resolved == expected


def test_subpath_helpers_respect_custom_data_dir(tmp_path):
    custom_dir = str(tmp_path / "custom_scope")
    assert get_default_db_path(custom_dir) == os.path.join(custom_dir, "ether.db")
    assert get_default_settings_path(custom_dir) == os.path.join(custom_dir, "settings.json")
    assert get_default_scratchpad_path(custom_dir) == os.path.join(custom_dir, "scratchpad.md")
    assert get_default_exports_dir(custom_dir) == os.path.join(custom_dir, "exports")
    assert get_default_reports_dir(custom_dir) == os.path.join(custom_dir, "reports")
    assert get_default_logs_dir(custom_dir) == os.path.join(custom_dir, "logs")
    assert not hasattr(paths, "get_action_log_path")
