"""Forensic session log management, 64KB disk spooling, and cryptographic audit manifest.

Deep module encapsulating session-partitioned log directories, unmutated stream capture,
continuous SHA-256 hash chaining, and session-close lifecycle compression.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ether import paths
from ether.common import strip_ansi

logger = logging.getLogger(__name__)


class LogSpooler:
    """High-throughput disk spooler with 64KB buffering, ANSI stripping, and \\r overwrite normalization."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path
        self._file = None
        self._pending_cr_buffer = ""
        self._bytes_written = 0
        if self.log_path:
            try:
                log_dir = os.path.dirname(os.path.abspath(self.log_path))
                if log_dir:
                    os.makedirs(log_dir, mode=0o700, exist_ok=True)
                self._file = open(
                    self.log_path, "a", encoding="utf-8", errors="replace", buffering=65536
                )
                try:
                    os.chmod(self.log_path, 0o600)
                except OSError:
                    pass
            except Exception as e:
                logger.error(f"Failed to open log file {self.log_path}: {e}")

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    def write(self, chunk: str) -> None:
        if self._file:
            try:
                clean_chunk = strip_ansi(chunk)
                if not clean_chunk:
                    return

                combined = (self._pending_cr_buffer + clean_chunk).replace("\r\n", "\n")
                if "\r" in combined:
                    lines = combined.split("\n")
                    self._pending_cr_buffer = lines.pop()
                    collapsed_lines = [line.split("\r")[-1] for line in lines]
                    if collapsed_lines:
                        payload = "\n".join(collapsed_lines) + "\n"
                        self._file.write(payload)
                        self._bytes_written += len(payload.encode("utf-8", errors="replace"))
                else:
                    self._pending_cr_buffer = ""
                    self._file.write(combined)
                    self._bytes_written += len(combined.encode("utf-8", errors="replace"))
            except Exception:
                pass

    def flush(self) -> None:
        if self._file:
            try:
                if self._pending_cr_buffer:
                    final_line = self._pending_cr_buffer.split("\r")[-1]
                    if final_line:
                        payload = final_line + "\n"
                        self._file.write(payload)
                        self._bytes_written += len(payload.encode("utf-8", errors="replace"))
                    self._pending_cr_buffer = ""
                self._file.flush()
            except Exception:
                pass

    def close(self) -> None:
        if self._file:
            try:
                self.flush()
                self._file.close()
            except Exception:
                pass
            finally:
                self._file = None


@dataclass(frozen=True)
class AuditRecord:
    index: int
    timestamp: str
    action_id: str
    tool: str
    target: str
    exit_code: int
    log_file: str
    byte_size: int
    log_sha256: str
    prev_entry_sha256: str
    entry_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditRecord:
        return cls(**data)


class ForensicLogManager:
    """Deep module managing session-partitioned logs and append-only tamper-evident manifests."""

    GENESIS_HASH = "0" * 64

    @staticmethod
    def sanitize_target_for_filename(target: str) -> str:
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", target)
        return sanitized[:40] or "target"

    @classmethod
    def get_session_dir(cls, session_id: str, data_dir: Optional[str] = None) -> Path:
        base = paths.get_default_logs_dir(data_dir)
        session_dir = Path(base) / "sessions" / session_id
        session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return session_dir

    @classmethod
    def get_manifest_path(cls, session_id: str, data_dir: Optional[str] = None) -> Path:
        return cls.get_session_dir(session_id, data_dir) / "audit_manifest.jsonl"

    @classmethod
    def open_action_spool(
        cls,
        session_id: str,
        action_id: str,
        tool: str,
        target: str,
        data_dir: Optional[str] = None,
    ) -> Tuple[LogSpooler, Path]:
        session_dir = cls.get_session_dir(session_id, data_dir)
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sanitized_target = cls.sanitize_target_for_filename(target)
        short_id = str(action_id)[:8]
        filename = f"{now_str}_{tool}_{sanitized_target}_{short_id}.log"
        log_path = session_dir / filename
        spooler = LogSpooler(str(log_path))
        return spooler, log_path

    @classmethod
    def compute_file_sha256(cls, file_path: Path) -> str:
        if not file_path.is_file():
            return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def record_action_completion(
        cls,
        session_id: str,
        action_id: str,
        tool: str,
        target: str,
        exit_code: int,
        log_path: Path,
        data_dir: Optional[str] = None,
    ) -> AuditRecord:
        manifest_path = cls.get_manifest_path(session_id, data_dir)
        records = cls.query_session_audit(session_id, data_dir)
        index = len(records)
        prev_entry_sha256 = records[-1].entry_sha256 if records else cls.GENESIS_HASH

        log_sha256 = cls.compute_file_sha256(log_path)
        byte_size = log_path.stat().st_size if log_path.is_file() else 0
        now_iso = datetime.now(timezone.utc).isoformat()

        entry_payload = (
            f"{prev_entry_sha256}:{index}:{now_iso}:{action_id}:{tool}:{target}:"
            f"{exit_code}:{log_path.name}:{log_sha256}:{byte_size}"
        )
        entry_sha256 = hashlib.sha256(entry_payload.encode("utf-8")).hexdigest()

        record = AuditRecord(
            index=index,
            timestamp=now_iso,
            action_id=action_id,
            tool=tool,
            target=target,
            exit_code=exit_code,
            log_file=log_path.name,
            byte_size=byte_size,
            log_sha256=log_sha256,
            prev_entry_sha256=prev_entry_sha256,
            entry_sha256=entry_sha256,
        )

        with open(manifest_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict()) + "\n")
        try:
            os.chmod(manifest_path, 0o600)
        except OSError:
            pass

        return record

    @classmethod
    def query_session_audit(
        cls, session_id: str, data_dir: Optional[str] = None
    ) -> List[AuditRecord]:
        manifest_path = cls.get_manifest_path(session_id, data_dir)
        if not manifest_path.is_file():
            return []
        records: List[AuditRecord] = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    records.append(AuditRecord.from_dict(data))
                except Exception as e:
                    logger.warning(f"Malformed audit manifest line in {manifest_path}: {e}")
        return records

    @classmethod
    def verify_session_audit(
        cls, session_id: str, data_dir: Optional[str] = None
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        manifest_path = cls.get_manifest_path(session_id, data_dir)
        session_dir = cls.get_session_dir(session_id, data_dir)
        if not manifest_path.is_file():
            return True, []

        records = cls.query_session_audit(session_id, data_dir)
        results: List[Dict[str, Any]] = []
        overall_valid = True
        expected_prev = cls.GENESIS_HASH

        for r in records:
            prev_ok = r.prev_entry_sha256 == expected_prev
            expected_payload = (
                f"{r.prev_entry_sha256}:{r.index}:{r.timestamp}:{r.action_id}:{r.tool}:{r.target}:"
                f"{r.exit_code}:{r.log_file}:{r.log_sha256}:{r.byte_size}"
            )
            recomputed_entry_sha = hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
            entry_ok = recomputed_entry_sha == r.entry_sha256

            log_file_path = session_dir / r.log_file
            file_ok = False
            if log_file_path.is_file():
                current_file_sha = cls.compute_file_sha256(log_file_path)
                file_ok = current_file_sha == r.log_sha256
            elif (session_dir / f"{r.log_file}.gz").is_file():
                with gzip.open(session_dir / f"{r.log_file}.gz", "rb") as gz_f:
                    h = hashlib.sha256()
                    for chunk in iter(lambda: gz_f.read(65536), b""):
                        h.update(chunk)
                    file_ok = h.hexdigest() == r.log_sha256

            is_valid = prev_ok and entry_ok and file_ok
            if not is_valid:
                overall_valid = False

            results.append({
                "index": r.index,
                "action_id": r.action_id,
                "tool": r.tool,
                "log_file": r.log_file,
                "hash_chain_valid": prev_ok and entry_ok,
                "file_hash_valid": file_ok,
                "valid": is_valid,
            })
            expected_prev = r.entry_sha256

        return overall_valid, results

    @classmethod
    def compress_session_logs(
        cls, session_id: str, data_dir: Optional[str] = None
    ) -> List[Path]:
        session_dir = cls.get_session_dir(session_id, data_dir)
        compressed: List[Path] = []
        for file in session_dir.glob("*.log"):
            gz_path = file.with_name(f"{file.name}.gz")
            with open(file, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            try:
                os.chmod(gz_path, 0o600)
                file.unlink()
            except OSError:
                pass
            compressed.append(gz_path)
        return compressed

    @classmethod
    def find_action_log(
        cls,
        action_id: str,
        session_id: Optional[str] = None,
        data_dir: Optional[str] = None,
    ) -> Optional[Path]:
        """Locate the `.log` or `.log.gz` spool file for an action in `logs/sessions/<session_id>/`."""
        sessions_root = Path(paths.get_default_logs_dir(data_dir)) / "sessions"
        if not sessions_root.is_dir():
            return None

        short_id = str(action_id)[:8]
        search_dirs: List[Path]
        if session_id is not None:
            candidate = sessions_root / session_id
            if not candidate.is_dir():
                return None
            search_dirs = [candidate]
        else:
            search_dirs = [d for d in sessions_root.iterdir() if d.is_dir()]

        for d in search_dirs:
            for ext in (".log", ".log.gz"):
                matches = sorted(
                    d.glob(f"*_{short_id}{ext}"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if matches:
                    return matches[0]
        return None

    @classmethod
    def read_action_log(
        cls,
        action_id: str,
        session_id: Optional[str] = None,
        tail_lines: int = 50,
        data_dir: Optional[str] = None,
    ) -> Optional[str]:
        """Read the tail (or full contents if tail_lines <= 0) of an action's `.log` or `.log.gz`."""
        log_path = cls.find_action_log(action_id, session_id=session_id, data_dir=data_dir)
        if log_path is None:
            return None

        if log_path.suffix == ".gz":
            with gzip.open(log_path, "rt", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        else:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

        if tail_lines > 0:
            return "".join(lines[-tail_lines:])
        return "".join(lines)
