"""Unit tests for ContainerizedToolRunner and PreflightVerifier container fallback."""

from unittest.mock import patch

import pytest

from ether.core.container import ContainerizedToolRunner
from ether.gateway.gate import GatePolicy
from ether.gateway.preflight import PreflightVerifier
from ether.registry.registry import ToolRegistry


@pytest.mark.fast
def test_container_runner_disabled_by_default(monkeypatch):
    monkeypatch.delenv("ETHER_CONTAINER_FALLBACK", raising=False)
    assert ContainerizedToolRunner.is_enabled() is False
    assert ContainerizedToolRunner.is_available() is False


@pytest.mark.fast
def test_container_runner_enabled_and_available(monkeypatch):
    monkeypatch.setenv("ETHER_CONTAINER_FALLBACK", "1")
    pinned = "ghcr.io/ether/arsenal@sha256:" + ("a" * 64)
    monkeypatch.setenv("ETHER_CONTAINER_IMAGE", pinned)

    assert ContainerizedToolRunner.is_enabled() is True
    assert ContainerizedToolRunner.get_image() == pinned

    monkeypatch.setenv("ETHER_CONTAINER_IMAGE", "ghcr.io/ether/arsenal:v1.0.0")
    with pytest.raises(ValueError, match="digest-pinned"):
        ContainerizedToolRunner.get_image()

    monkeypatch.setenv("ETHER_CONTAINER_ALLOW_MUTABLE_TAG", "1")
    assert ContainerizedToolRunner.get_image() == "ghcr.io/ether/arsenal:v1.0.0"

    with patch("shutil.which", return_value="/usr/bin/podman"):
        assert ContainerizedToolRunner.get_runtime() == "/usr/bin/podman"
        assert ContainerizedToolRunner.is_available() is True


@pytest.mark.fast
def test_container_runner_should_use_container(monkeypatch):
    monkeypatch.setenv("ETHER_CONTAINER_FALLBACK", "1")

    # In-process coroutines and shell must never use container
    assert (
        ContainerizedToolRunner.should_use_container("stealth_scan", execution_tier="coroutine")
        is False
    )
    assert ContainerizedToolRunner.should_use_container("sudo") is False
    assert ContainerizedToolRunner.should_use_container("bash") is False

    # External binary when runtime exists and local binary is missing
    with patch("shutil.which") as mock_which:

        def _mock_which(name):
            if name in ("podman", "docker"):
                return f"/usr/bin/{name}"
            if name == "missing_tool":
                return None
            if name == "installed_tool":
                return "/usr/bin/installed_tool"
            return None

        mock_which.side_effect = _mock_which

        assert ContainerizedToolRunner.should_use_container("installed_tool") is False
        assert ContainerizedToolRunner.should_use_container("missing_tool") is True


@pytest.mark.fast
def test_container_runner_build_command(monkeypatch):
    pinned = "ghcr.io/ether/arsenal@sha256:" + ("b" * 64)
    monkeypatch.setenv("ETHER_CONTAINER_IMAGE", pinned)
    with patch("shutil.which", return_value="/usr/bin/podman"):
        cmd = ContainerizedToolRunner.build_container_command(
            command=["sqlmap", "-u", "http://target.com"],
            cwd="/tmp/work",
            env={"FOO": "bar", "ETHER_TOKEN": "secret"},
        )
        assert cmd[0] == "/usr/bin/podman"
        assert "run" in cmd
        assert "--rm" in cmd
        assert "--read-only" in cmd
        assert "--cap-drop=ALL" in cmd
        assert pinned in cmd
        assert "sqlmap" in cmd
        assert "-u" in cmd
        # Scrubbed secret
        assert not any("ETHER_TOKEN" in arg for arg in cmd)
        assert any("FOO=bar" in arg for arg in cmd)


@pytest.mark.fast
def test_preflight_verifier_container_fallback_warning(monkeypatch):
    monkeypatch.setenv("ETHER_CONTAINER_FALLBACK", "1")
    monkeypatch.setenv("ETHER_CONTAINER_IMAGE", "ghcr.io/ether/arsenal@sha256:" + ("c" * 64))

    class FakeAdapter:
        name = "mock_missing"
        binary = "mock_missing"
        execution_tier = "subprocess"

        def validate_install(self):
            return False

        def build_command(self, target, params):
            return ["mock_missing", "target"]

    reg = ToolRegistry(tools_dir=None)
    reg.tools["mock_missing"] = {"adapter": FakeAdapter(), "manifest": None}

    verifier = PreflightVerifier(registry=reg, policy=GatePolicy.SAFE)

    with patch("shutil.which") as mock_which:

        def _mock_which(name):
            if name == "podman":
                return "/usr/bin/podman"
            return None

        mock_which.side_effect = _mock_which

        report = verifier.verify("mock_missing", target="scanme.nmap.org")
        assert report.is_valid is True
        assert report.has_warnings is True
        warning_titles = [w.title for w in report.warnings]
        assert any("container fallback" in t for t in warning_titles)
