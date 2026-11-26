"""Two-phase atomic session sealer with recovery journal and Ed25519 audit signing."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ether import paths
from ether.common.forensic_log import ForensicLogManager

GENESIS_HASH = ForensicLogManager.GENESIS_HASH


class SealState(str, Enum):
    """Two-phase commit lifecycle states for atomic session sealing."""

    ACTIVE = "ACTIVE"
    SEALING = "SEALING"
    COMPRESSING = "COMPRESSING"
    SEALED = "SEALED"


@dataclass(frozen=True)
class SealReceipt:
    """Cryptographically signed receipt proving atomic session closure and audit integrity."""

    session_id: str
    state: str
    sealed_at: str
    manifest_sha256: str
    chain_head_sha256: str
    record_count: int
    compressed_logs: List[str]
    signature_b64: str
    public_key_b64: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SealReceipt:
        return cls(**data)


def _canonical_receipt_payload(
    session_id: str,
    sealed_at: str,
    manifest_sha256: str,
    chain_head_sha256: str,
    record_count: int,
) -> bytes:
    payload = {
        "session_id": session_id,
        "sealed_at": sealed_at,
        "manifest_sha256": manifest_sha256,
        "chain_head_sha256": chain_head_sha256,
        "record_count": record_count,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    """Write JSON atomically with 0o600 permissions to prevent TOCTOU races."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path = path.with_suffix(f"{path.suffix}.tmp.{os.getpid()}")
    raw = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    fd = os.open(str(tmp_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp_path, path)


def _load_or_provision_keypair(
    private_key: Optional[bytes],
    data_dir: Optional[str | Path],
    is_memory_store: bool,
) -> Tuple[Ed25519PrivateKey, bytes]:
    """Load an explicit Ed25519 key, or auto-provision a 0o600 node key for persistent stores."""
    if private_key is not None:
        if len(private_key) == 32:
            priv = Ed25519PrivateKey.from_private_bytes(private_key)
        else:
            priv = serialization.load_pem_private_key(private_key, password=None)  # type: ignore[assignment]
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub_bytes

    if is_memory_store:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv, pub_bytes

    base_dir = Path(data_dir) if data_dir is not None else Path(paths.get_default_data_dir())
    key_path = base_dir / "keys" / "audit_signing.key"
    if key_path.exists():
        raw = key_path.read_bytes()
        if len(raw) == 32:
            priv = Ed25519PrivateKey.from_private_bytes(raw)
        else:
            priv = serialization.load_pem_private_key(raw, password=None)  # type: ignore[assignment]
    else:
        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        tmp = key_path.with_suffix(".key.tmp")
        fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, key_path)

    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


class SessionSealer:
    """Two-phase atomic session sealer with persistent recovery journal and Ed25519 signing."""

    def __init__(self, store: Any = None, data_dir: Optional[str | Path] = None) -> None:
        self.store = store
        self.data_dir = data_dir

    def _session_dir(self, session_id: str) -> Path:
        data_dir_str = str(self.data_dir) if self.data_dir is not None else None
        return ForensicLogManager.get_session_dir(session_id, data_dir=data_dir_str)

    def _journal_path(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "seal_journal.json"

    def _receipt_path(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "seal_receipt.json"

    def get_seal_state(self, session_id: str) -> SealState:
        """Return the current seal state from the recovery journal or receipt."""
        receipt_path = self._receipt_path(session_id)
        if receipt_path.exists():
            return SealState.SEALED
        journal_path = self._journal_path(session_id)
        if journal_path.exists():
            try:
                data = json.loads(journal_path.read_text(encoding="utf-8"))
                return SealState(data.get("state", SealState.ACTIVE.value))
            except Exception:
                return SealState.ACTIVE
        return SealState.ACTIVE

    async def seal_session(
        self,
        session_id: str,
        private_key: Optional[bytes] = None,
    ) -> SealReceipt:
        """Atomically seal a session via two-phase commit and sign its audit manifest."""
        is_memory = bool(
            self.store is not None and getattr(self.store, "db_path", "") == ":memory:"
        )
        hermetic_memory = is_memory and self.data_dir is None
        now_iso = datetime.now(timezone.utc).isoformat()
        data_dir_str = str(self.data_dir) if self.data_dir is not None else None

        if not hermetic_memory:
            journal_path = self._journal_path(session_id)
            # Phase 1: Mark SEALING in recovery journal
            _write_json_atomic(
                journal_path,
                {"session_id": session_id, "state": SealState.SEALING.value, "updated_at": now_iso},
            )

            # Phase 2: Transition to COMPRESSING and compress raw session logs
            _write_json_atomic(
                journal_path,
                {
                    "session_id": session_id,
                    "state": SealState.COMPRESSING.value,
                    "updated_at": now_iso,
                },
            )
            compressed_paths = ForensicLogManager.compress_session_logs(
                session_id, data_dir=data_dir_str
            )

            # Compute audit manifest hash and chain head
            manifest_path = ForensicLogManager.get_manifest_path(session_id, data_dir=data_dir_str)
            if manifest_path.exists():
                manifest_bytes = manifest_path.read_bytes()
                manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
                records = ForensicLogManager.query_session_audit(session_id, data_dir=data_dir_str)
                chain_head = records[-1].entry_sha256 if records else GENESIS_HASH
                record_count = len(records)
            else:
                manifest_sha256 = hashlib.sha256(b"").hexdigest()
                chain_head = GENESIS_HASH
                record_count = 0
        else:
            compressed_paths = []
            manifest_sha256 = hashlib.sha256(b"").hexdigest()
            chain_head = GENESIS_HASH
            record_count = 0

        # Sign receipt with Ed25519
        priv_key, pub_bytes = _load_or_provision_keypair(
            private_key=private_key,
            data_dir=self.data_dir,
            is_memory_store=is_memory,
        )
        payload = _canonical_receipt_payload(
            session_id=session_id,
            sealed_at=now_iso,
            manifest_sha256=manifest_sha256,
            chain_head_sha256=chain_head,
            record_count=record_count,
        )
        signature = priv_key.sign(payload)

        receipt = SealReceipt(
            session_id=session_id,
            state=SealState.SEALED.value,
            sealed_at=now_iso,
            manifest_sha256=manifest_sha256,
            chain_head_sha256=chain_head,
            record_count=record_count,
            compressed_logs=[Path(p).name for p in compressed_paths],
            signature_b64=base64.b64encode(signature).decode("ascii"),
            public_key_b64=base64.b64encode(pub_bytes).decode("ascii"),
        )

        # Persist SQLite CLOSED status via WriteQueue if store is attached
        if self.store is not None:
            await self.store._mark_session_closed_sql(session_id)

        if not hermetic_memory:
            _write_json_atomic(self._receipt_path(session_id), receipt.to_dict())
            _write_json_atomic(
                journal_path,
                {"session_id": session_id, "state": SealState.SEALED.value, "updated_at": now_iso},
            )
        return receipt

    @classmethod
    def verify_seal(
        cls,
        session_id: str,
        data_dir: Optional[str | Path] = None,
        public_key: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """Verify a sealed session's Ed25519 receipt and underlying SHA-256 audit chain."""
        data_dir_str = str(data_dir) if data_dir is not None else None
        receipt_path = (
            ForensicLogManager.get_session_dir(session_id, data_dir=data_dir_str)
            / "seal_receipt.json"
        )
        if not receipt_path.exists():
            return False, f"No seal receipt found for session {session_id}."

        try:
            receipt = SealReceipt.from_dict(json.loads(receipt_path.read_text(encoding="utf-8")))
        except Exception as e:
            return False, f"Corrupt seal receipt: {e}"

        # Verify underlying hash chain and compressed logs
        chain_ok, chain_msg = ForensicLogManager.verify_session_audit(
            session_id, data_dir=data_dir_str
        )
        if not chain_ok:
            return False, f"Audit chain verification failed: {chain_msg}"

        manifest_path = ForensicLogManager.get_manifest_path(session_id, data_dir=data_dir_str)
        current_manifest_sha = (
            hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            if manifest_path.exists()
            else hashlib.sha256(b"").hexdigest()
        )
        if current_manifest_sha != receipt.manifest_sha256:
            return False, "Audit manifest SHA-256 mismatch against seal receipt."

        try:
            pub_raw = (
                public_key
                if public_key is not None
                else base64.b64decode(receipt.public_key_b64.encode("ascii"))
            )
            pub_obj = Ed25519PublicKey.from_public_bytes(pub_raw)
            sig_raw = base64.b64decode(receipt.signature_b64.encode("ascii"))
            payload = _canonical_receipt_payload(
                session_id=receipt.session_id,
                sealed_at=receipt.sealed_at,
                manifest_sha256=receipt.manifest_sha256,
                chain_head_sha256=receipt.chain_head_sha256,
                record_count=receipt.record_count,
            )
            pub_obj.verify(sig_raw, payload)
        except InvalidSignature:
            return False, "Ed25519 signature verification failed (receipt tampered)."
        except Exception as e:
            return False, f"Signature verification error: {e}"

        return True, f"Verified Ed25519 seal and {receipt.record_count} chained audit record(s)."
