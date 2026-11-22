"""Unit tests for centralized system logging, flight recorder breadcrumbs,

and crash trap monitoring subsystem in Ether.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import sys

import pytest

from ether.common.logging import (
    FlightRecorder,
    SanitizingLogFormatter,
    SecureRotatingFileHandler,
    get_recent_crash_summary,
    install_global_exception_traps,
    record_breadcrumb,
    setup_system_logging,
)

pytestmark = pytest.mark.fast


def test_secure_rotating_file_handler_permissions(tmp_path):
    """Ensure SecureRotatingFileHandler creates log files with strict 0o600 permissions."""
    log_dir = tmp_path / "logs"
    log_file = log_dir / "ether.log"

    handler = SecureRotatingFileHandler(
        filename=str(log_file),
        maxBytes=1024,
        backupCount=2,
        encoding="utf-8",
    )
    logger = logging.getLogger("test_perms")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("First secure log entry")
    handler.flush()
    handler.close()
    logger.removeHandler(handler)

    assert log_file.exists()
    mode = stat.S_IMODE(os.stat(log_file).st_mode)
    assert mode == 0o600, f"Expected 0o600 mode, got {oct(mode)}"


def test_secure_rotating_file_handler_rollover_permissions(tmp_path):
    """Ensure log rotation preserves 0o600 permissions across all rotated backups."""
    log_file = tmp_path / "logs" / "ether.log"
    handler = SecureRotatingFileHandler(
        filename=str(log_file),
        maxBytes=200,
        backupCount=2,
        encoding="utf-8",
    )
    logger = logging.getLogger("test_rollover")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Write enough data to trigger rollover
    for i in range(25):
        logger.info("Log rollover test record payload line %d: %s", i, "X" * 30)

    handler.flush()
    handler.close()
    logger.removeHandler(handler)

    assert log_file.exists()
    mode = stat.S_IMODE(os.stat(log_file).st_mode)
    assert mode == 0o600

    backup_1 = tmp_path / "logs" / "ether.log.1"
    if backup_1.exists():
        backup_mode = stat.S_IMODE(os.stat(backup_1).st_mode)
        assert backup_mode == 0o600


def test_sanitizing_log_formatter_redacts_secrets():
    """Ensure SanitizingLogFormatter redacts API keys, tokens, passwords, and private keys."""
    formatter = SanitizingLogFormatter(fmt="%(message)s")

    def format_msg(msg: str) -> str:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        return formatter.format(record)

    # API keys and bearer tokens
    assert "***REDACTED***" in format_msg("Connecting with api_key='sk-123456789012345678901234'")
    assert "***REDACTED***" in format_msg("Authorization: Bearer my_secret_token_1234567890")
    assert "***REDACTED***" in format_msg("Using token: ghp_123456789012345678901234")

    # Passwords in URLs
    url_msg = format_msg("Connecting to http://admin:supersecret@127.0.0.1:8080/api")
    assert "supersecret" not in url_msg
    assert "://admin:***@" in url_msg

    # Private keys
    priv_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END OPENSSH PRIVATE KEY-----"
    redacted_priv = format_msg(f"Loaded key:\n{priv_key}")
    assert "MIIEowIBAAKCAQEA" not in redacted_priv
    assert "[***REDACTED***]" in redacted_priv


def test_flight_recorder_ring_buffer_bounded():
    """Ensure FlightRecorder maintains a bounded in-memory buffer."""
    recorder = FlightRecorder(maxlen=5)
    for i in range(10):
        recorder.record("test", f"Event {i}", idx=i)

    crumbs = recorder.get_breadcrumbs()
    assert len(crumbs) == 5
    assert crumbs[0].message == "Event 5"
    assert crumbs[-1].message == "Event 9"

    text = recorder.format_breadcrumbs()
    assert "Event 9" in text
    assert "Event 0" not in text

    recorder.clear()
    assert len(recorder.get_breadcrumbs()) == 0


def test_global_exception_traps_capture_unhandled_errors(tmp_path):
    """Ensure global exception trap hooks write fatal crashes and breadcrumbs to system log."""
    setup_system_logging(data_dir=str(tmp_path), verbose=True, force=True)
    FlightRecorder.get_instance().clear()
    record_breadcrumb("test", "Preparing unstable calculation", param=42)

    install_global_exception_traps()

    try:
        raise RuntimeError("Synthetic fatal division error")
    except RuntimeError:
        exc_type, exc_val, exc_tb = sys.exc_info()
        sys.excepthook(exc_type, exc_val, exc_tb)

    log_file = tmp_path / "logs" / "ether.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "FATAL UNHANDLED EXCEPTION" in content
    assert "Synthetic fatal division error" in content
    assert "Preparing unstable calculation" in content


@pytest.mark.asyncio
async def test_asyncio_exception_handler_captures_task_faults(tmp_path):
    """Ensure asyncio event loop trap logs unhandled task faults with breadcrumbs."""
    setup_system_logging(data_dir=str(tmp_path), verbose=True, force=True)
    loop = asyncio.get_running_loop()
    install_global_exception_traps(loop=loop)

    record_breadcrumb("async", "Scheduled background task")

    # Dispatch context error to handler
    context = {
        "message": "Task raised unhandled exception",
        "exception": ValueError("Corrupted background buffer"),
    }
    loop.call_exception_handler(context)

    log_file = tmp_path / "logs" / "ether.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "UNHANDLED ASYNCIO EXCEPTION" in content
    assert "Corrupted background buffer" in content


def test_get_recent_crash_summary_parsing(tmp_path):
    """Ensure get_recent_crash_summary parses recent crash blocks."""
    log_dir = tmp_path / "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = log_dir / "ether.log"

    log_content = (
        "2026-11-21 09:30:00 [INFO] [ether] [MainThread] Normal startup\n"
        "2026-11-21 09:30:15 [CRITICAL] [ether] [MainThread] FATAL UNHANDLED EXCEPTION ESCAPED TO PYTHON INTERPRETER:\n"
        "ValueError: Rapid cancellation fault\n"
        "=== FLIGHT RECORDER BREADCRUMBS ===\n"
        "[2026-11-21 09:30:14.100] [SYSTEM] Initializing\n"
    )
    log_file.write_text(log_content, encoding="utf-8")

    summary = get_recent_crash_summary(str(tmp_path))
    assert summary is not None
    assert summary["timestamp"] == "2026-11-21 09:30:15"
    assert "FATAL UNHANDLED EXCEPTION" in summary["summary"]
    assert "Rapid cancellation fault" in summary["block"]
