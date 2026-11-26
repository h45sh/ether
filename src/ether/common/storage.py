"""Deep module managing storage quotas, log retention, and transparent compression."""

from __future__ import annotations

import gzip
import json
import logging
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Set, Union

logger = logging.getLogger(__name__)


@dataclass
class StoragePruneReport:
    """Telemetry report produced by retention policy enforcement."""

    total_scanned_bytes: int = 0
    compressed_files: int = 0
    pruned_files: int = 0
    freed_bytes: int = 0
    skipped_forensic_files: int = 0
    remaining_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StorageLifecycleManager:
    """Enforces disk retention quotas, log compression, and forensic chain preservation."""

    @staticmethod
    def find_protected_forensic_logs(logs_dir: Path) -> Set[Path]:
        """Scan logs_dir for audit_manifest.jsonl files and extract tracked log paths.

        Preserves ForensicLogManager SHA-256 chain of custody (Tier 1 Frozen Core).
        """
        protected_paths: Set[Path] = set()
        if not logs_dir.is_dir():
            return protected_paths

        for manifest_path in logs_dir.rglob("audit_manifest.jsonl"):
            try:
                with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            log_file = record.get("log_file")
                            if log_file:
                                raw_path = Path(log_file)
                                if raw_path.is_absolute():
                                    protected_paths.add(raw_path.resolve())
                                else:
                                    protected_paths.add((manifest_path.parent / raw_path).resolve())
                        except Exception:
                            continue
            except Exception as e:
                logger.warning(f"Error reading manifest {manifest_path}: {e}")

        return protected_paths

    @classmethod
    def enforce_retention_policy(
        cls,
        logs_dir: Union[Path, str],
        max_disk_mb: int = 1000,
        max_age_days: int = 30,
        include_forensic: bool = False,
        compress_older_than_seconds: float = 3600.0,
    ) -> StoragePruneReport:
        """Enforce log compression and retention quotas.

        Args:
            logs_dir: Path to directory containing session and spool logs.
            max_disk_mb: Maximum total size in MB for logs_dir.
            max_age_days: Max age in days before pruning eligible logs.
            include_forensic: If True, also compress/prune audit_manifest-tracked logs.
            compress_older_than_seconds: Compress eligible .log files older than this.
        """
        root = Path(logs_dir).resolve()
        report = StoragePruneReport()

        if not root.is_dir():
            return report

        protected = set() if include_forensic else cls.find_protected_forensic_logs(root)
        now = time.time()
        max_age_seconds = max_age_days * 86400.0
        max_disk_bytes = max_disk_mb * 1024 * 1024

        all_files: List[Path] = []
        for p in root.rglob("*"):
            if p.is_file() and not p.name.startswith("."):
                all_files.append(p)

        report.total_scanned_bytes = sum(f.stat().st_size for f in all_files if f.exists())

        # Phase 1: Compress uncompressed .log files older than compress_older_than_seconds
        for fpath in list(all_files):
            if not fpath.exists():
                continue
            is_log_candidate = (
                fpath.suffix == ".log" or fpath.name.startswith("system.log.")
            ) and not fpath.name.endswith((".gz", ".zst")) and fpath.name != "audit_manifest.jsonl"
            if is_log_candidate:
                if fpath in protected:
                    report.skipped_forensic_files += 1
                    continue

                mtime = fpath.stat().st_mtime
                if (now - mtime) >= compress_older_than_seconds:
                    gz_path = fpath.with_suffix(".log.gz")
                    try:
                        orig_size = fpath.stat().st_size
                        with open(fpath, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                        compressed_size = gz_path.stat().st_size
                        fpath.unlink()
                        report.compressed_files += 1
                        report.freed_bytes += max(0, orig_size - compressed_size)
                        # Replace in tracked list
                        all_files.remove(fpath)
                        all_files.append(gz_path)
                    except Exception as e:
                        logger.error(f"Failed to compress {fpath}: {e}")

        # Phase 2: Prune files older than max_age_days
        remaining_files: List[Path] = []
        for fpath in all_files:
            if not fpath.exists():
                continue
            if fpath.name == "audit_manifest.jsonl" or fpath in protected:
                remaining_files.append(fpath)
                continue

            mtime = fpath.stat().st_mtime
            if (now - mtime) > max_age_seconds:
                try:
                    size = fpath.stat().st_size
                    fpath.unlink()
                    report.pruned_files += 1
                    report.freed_bytes += size
                except Exception as e:
                    logger.error(f"Failed to prune old log {fpath}: {e}")
            else:
                remaining_files.append(fpath)

        # Phase 3: Enforce disk watermark quota
        current_total = sum(f.stat().st_size for f in remaining_files if f.exists())
        if current_total > max_disk_bytes:
            # Sort eligible files by mtime ascending (oldest first)
            eligible_to_prune = [
                f for f in remaining_files
                if f.name != "audit_manifest.jsonl" and (include_forensic or f not in protected)
            ]
            eligible_to_prune.sort(key=lambda f: f.stat().st_mtime)

            for fpath in eligible_to_prune:
                if current_total <= max_disk_bytes:
                    break
                try:
                    size = fpath.stat().st_size
                    fpath.unlink()
                    report.pruned_files += 1
                    report.freed_bytes += size
                    current_total -= size
                except Exception as e:
                    logger.error(f"Failed to prune over-quota file {fpath}: {e}")

        report.remaining_bytes = sum(f.stat().st_size for f in root.rglob("*") if f.is_file())
        return report
