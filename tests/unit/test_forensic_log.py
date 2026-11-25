"""Unit tests for ForensicLogManager, LogSpooler, and cryptographic hash chaining."""

from pathlib import Path

import pytest

from ether.common.forensic_log import ForensicLogManager, LogSpooler

pytestmark = pytest.mark.fast


def test_log_spooler_streaming(tmp_path: Path):
    log_file = tmp_path / "test_action.log"
    spooler = LogSpooler(str(log_file))

    spooler.write("\x1b[32m[+] Starting discovery\x1b[0m\n")
    spooler.write("Progress: 50%\rProgress: 100%\n")
    spooler.write("[+] Host: 10.0.0.1 open\n")
    spooler.close()

    assert log_file.is_file()
    content = log_file.read_text(encoding="utf-8")
    assert "\x1b" not in content
    assert "[+] Starting discovery" in content
    assert "Progress: 100%" in content
    assert "[+] Host: 10.0.0.1 open" in content


def test_forensic_log_manager_audit_manifest_and_hash_chain(tmp_path: Path):
    session_id = "sess-forensic-test-123"
    data_dir = str(tmp_path)

    # Action 1
    spooler1, log_path1 = ForensicLogManager.open_action_spool(
        session_id=session_id,
        action_id="act-0001-aaaa",
        tool="nmap",
        target="10.0.0.1",
        data_dir=data_dir,
    )
    spooler1.write("Nmap scan report for 10.0.0.1\nPORT 80 open\n")
    spooler1.close()

    rec1 = ForensicLogManager.record_action_completion(
        session_id=session_id,
        action_id="act-0001-aaaa",
        tool="nmap",
        target="10.0.0.1",
        exit_code=0,
        log_path=log_path1,
        data_dir=data_dir,
    )
    assert rec1.index == 0
    assert rec1.prev_entry_sha256 == ForensicLogManager.GENESIS_HASH
    assert len(rec1.entry_sha256) == 64

    # Action 2
    spooler2, log_path2 = ForensicLogManager.open_action_spool(
        session_id=session_id,
        action_id="act-0002-bbbb",
        tool="gobuster",
        target="http://10.0.0.1",
        data_dir=data_dir,
    )
    spooler2.write("/admin (Status: 200)\n/login (Status: 302)\n")
    spooler2.close()

    rec2 = ForensicLogManager.record_action_completion(
        session_id=session_id,
        action_id="act-0002-bbbb",
        tool="gobuster",
        target="http://10.0.0.1",
        exit_code=0,
        log_path=log_path2,
        data_dir=data_dir,
    )
    assert rec2.index == 1
    assert rec2.prev_entry_sha256 == rec1.entry_sha256
    assert rec2.entry_sha256 != rec1.entry_sha256

    # Verify audit manifest
    is_valid, records = ForensicLogManager.verify_session_audit(session_id, data_dir=data_dir)
    assert is_valid
    assert len(records) == 2
    assert records[0]["valid"]
    assert records[1]["valid"]

    # Tampering test: modify log file content
    log_path1.write_text("TAMPERED CONTENT\n", encoding="utf-8")
    is_valid_tampered, tampered_records = ForensicLogManager.verify_session_audit(
        session_id, data_dir=data_dir
    )
    assert not is_valid_tampered
    assert not tampered_records[0]["valid"]
    assert not tampered_records[0]["file_hash_valid"]


def test_forensic_log_compression_lifecycle(tmp_path: Path):
    session_id = "sess-compress-test-456"
    data_dir = str(tmp_path)

    spooler, log_path = ForensicLogManager.open_action_spool(
        session_id=session_id,
        action_id="act-compress-1",
        tool="whois",
        target="example.com",
        data_dir=data_dir,
    )
    spooler.write("Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\n")
    spooler.close()

    ForensicLogManager.record_action_completion(
        session_id=session_id,
        action_id="act-compress-1",
        tool="whois",
        target="example.com",
        exit_code=0,
        log_path=log_path,
        data_dir=data_dir,
    )

    # Compress logs
    compressed = ForensicLogManager.compress_session_logs(session_id, data_dir=data_dir)
    assert len(compressed) == 1
    assert str(compressed[0]).endswith(".log.gz")
    assert not log_path.exists()
    assert compressed[0].exists()

    # Audit verification should still succeed over compressed logs
    is_valid, records = ForensicLogManager.verify_session_audit(session_id, data_dir=data_dir)
    assert is_valid
    assert records[0]["valid"]
    assert records[0]["file_hash_valid"]


def test_find_and_read_action_log_uncompressed_and_compressed(tmp_path: Path):
    session_id = "sess-read-log"
    data_dir = str(tmp_path)
    action_id = "12345678-aaaa-bbbb-cccc-1234567890ab"

    spooler, log_path = ForensicLogManager.open_action_spool(
        session_id=session_id,
        action_id=action_id,
        tool="nmap",
        target="10.0.0.1",
        data_dir=data_dir,
    )
    for i in range(10):
        spooler.write(f"line-{i}\n")
    spooler.close()

    # Find with explicit session_id
    found = ForensicLogManager.find_action_log(action_id, session_id=session_id, data_dir=data_dir)
    assert found == log_path

    # Find with session_id=None (searches across sessions)
    found_any = ForensicLogManager.find_action_log(action_id, data_dir=data_dir)
    assert found_any == log_path

    # Read tail_lines=3
    tail = ForensicLogManager.read_action_log(
        action_id, session_id=session_id, tail_lines=3, data_dir=data_dir
    )
    assert tail is not None
    assert "line-7" in tail
    assert "line-9" in tail
    assert "line-6" not in tail

    # Compress and verify find_action_log + read_action_log still work on .log.gz
    ForensicLogManager.compress_session_logs(session_id, data_dir=data_dir)
    found_gz = ForensicLogManager.find_action_log(action_id, session_id=session_id, data_dir=data_dir)
    assert found_gz is not None
    assert found_gz.name.endswith(".log.gz")

    tail_gz = ForensicLogManager.read_action_log(action_id, tail_lines=2, data_dir=data_dir)
    assert tail_gz is not None
    assert "line-8" in tail_gz
    assert "line-9" in tail_gz
    assert "line-7" not in tail_gz

    # Missing action returns None
    assert ForensicLogManager.find_action_log("nonexistent-id", data_dir=data_dir) is None
    assert ForensicLogManager.read_action_log("nonexistent-id", data_dir=data_dir) is None
