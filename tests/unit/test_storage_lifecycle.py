"""Unit tests for StorageLifecycleManager and log retention policy enforcement."""

import gzip
import json
import time
from pathlib import Path

import pytest

from ether.cli.commands.logs import handle_logs
from ether.cli.context import CliContext
from ether.common.storage import StorageLifecycleManager
from ether.gateway.gate import GatePolicy


@pytest.mark.fast
def test_storage_lifecycle_manager_compression_and_pruning(tmp_path: Path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)

    # 1. Create an old unchained log file
    old_log = logs_dir / "old_tool.log"
    old_log.write_text("A" * 10000)
    old_time = time.time() - 7200  # 2 hours old
    old_log.touch()
    import os

    os.utime(old_log, (old_time, old_time))

    # 2. Create a protected forensic log tracked in audit_manifest.jsonl
    session_dir = logs_dir / "sessions" / "sess-1"
    session_dir.mkdir(parents=True)
    forensic_log = session_dir / "forensic_action.log"
    forensic_log.write_text("CRITICAL FORENSIC DATA")
    os.utime(forensic_log, (old_time, old_time))

    manifest_file = session_dir / "audit_manifest.jsonl"
    manifest_record = {
        "timestamp": "2026-11-26T00:00:00Z",
        "action_id": "act-1",
        "tool": "nmap",
        "log_file": str(forensic_log.resolve()),
    }
    manifest_file.write_text(json.dumps(manifest_record) + "\n")

    # 3. Enforce policy without include_forensic
    report = StorageLifecycleManager.enforce_retention_policy(
        logs_dir=logs_dir,
        max_disk_mb=10,
        max_age_days=30,
        include_forensic=False,
        compress_older_than_seconds=3600.0,
    )

    assert report.compressed_files == 1
    assert not old_log.exists()
    assert (logs_dir / "old_tool.log.gz").exists()
    with gzip.open(logs_dir / "old_tool.log.gz", "rt") as f:
        assert f.read() == "A" * 10000

    # Forensic log must remain uncompressed and untouched
    assert forensic_log.exists()
    assert not (session_dir / "forensic_action.log.gz").exists()
    assert report.skipped_forensic_files >= 1


@pytest.mark.fast
def test_storage_lifecycle_manager_quota_prune(tmp_path: Path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)

    # Create several files exceeding quota
    f1 = logs_dir / "f1.log.gz"
    f2 = logs_dir / "f2.log.gz"
    f1.write_bytes(b"X" * 600)
    f2.write_bytes(b"Y" * 600)

    import os

    now = time.time()
    os.utime(f1, (now - 100, now - 100))  # older
    os.utime(f2, (now - 10, now - 10))

    # Total size = 1200 bytes. Set max_disk_mb to roughly 0.0008 MB (~800 bytes)
    # Using small max_disk_mb
    report = StorageLifecycleManager.enforce_retention_policy(
        logs_dir=logs_dir,
        max_disk_mb=0.0009,  # ~943 bytes
        max_age_days=30,
        include_forensic=False,
    )

    assert report.pruned_files == 1
    assert not f1.exists()  # Oldest pruned
    assert f2.exists()


@pytest.mark.fast
def test_cli_logs_prune(tmp_path: Path, capsys):
    from argparse import Namespace

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir(parents=True)
    f1 = logs_dir / "old.log"
    f1.write_text("data")
    import os

    old_time = time.time() - 10000
    os.utime(f1, (old_time, old_time))

    ctx = CliContext(
        data_dir=str(tmp_path),
        db_path=str(tmp_path / "test.db"),
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    args = Namespace(
        prune=True,
        max_disk_mb=1000,
        max_age_days=30,
        include_forensic=False,
        crashes=False,
    )

    ret = handle_logs(args, ctx)
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "compressed_files" in data
    assert "pruned_files" in data
