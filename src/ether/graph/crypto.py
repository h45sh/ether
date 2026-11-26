"""Transparent database cryptography and credential field protection (ChaCha20-Poly1305)."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ether import paths
from ether.common.crypto import derive_key_argon2id
from ether.common.secure_memory import wipe_buffer as zeroize_bytes

ENC_PREFIX = "enc:chacha20v1:"
SENSITIVE_CREDENTIAL_FIELDS = (
    "password",
    "secret_value",
    "token",
    "secret",
    "private_key",
    "api_key",
)


def is_credential_expired(data: Dict[str, Any], now: Optional[float] = None) -> bool:
    """Return True if a credential finding dictionary has passed its ttl_expires_at."""
    expires_at = data.get("ttl_expires_at")
    if expires_at is None:
        return False
    current = time.time() if now is None else now
    try:
        return float(expires_at) <= current
    except (TypeError, ValueError):
        return False


def _has_sqlcipher() -> bool:
    return importlib.util.find_spec("sqlcipher3") is not None


def _try_keyring_get(service: str, account: str) -> Optional[bytes]:
    if importlib.util.find_spec("keyring") is None:
        return None
    try:
        import keyring

        val = keyring.get_password(service, account)
        if val:
            return base64.b64decode(val.encode("ascii"))
    except Exception:
        pass
    return None


def _try_keyring_set(service: str, account: str, key: bytes) -> bool:
    if importlib.util.find_spec("keyring") is None:
        return False
    try:
        import keyring

        keyring.set_password(service, account, base64.b64encode(key).decode("ascii"))
        return True
    except Exception:
        return False


class CryptoEngine:
    """Transparent ChaCha20-Poly1305 field-level encryption engine with key versioning and rotation."""

    def __init__(
        self,
        key: Optional[bytes] = None,
        previous_keys: Optional[Sequence[bytes]] = None,
    ) -> None:
        if key is None:
            key = os.urandom(32)
        if len(key) != 32:
            raise ValueError("CryptoEngine requires a 32-byte encryption key.")
        self._key_buf = bytearray(key)
        self._aead = ChaCha20Poly1305(bytes(self._key_buf))
        self._key_id = hashlib.sha256(bytes(self._key_buf)).hexdigest()[:12]
        self._previous_aeads: Dict[str, ChaCha20Poly1305] = {}
        for prev in previous_keys or ():
            if len(prev) != 32:
                raise ValueError("CryptoEngine previous_keys entries must be 32 bytes.")
            prev_id = hashlib.sha256(prev).hexdigest()[:12]
            self._previous_aeads[prev_id] = ChaCha20Poly1305(prev)

    @property
    def key_id(self) -> str:
        """Return the active 12-char key identifier."""
        return self._key_id

    @classmethod
    def from_passphrase(
        cls, passphrase: str | bytes, salt: Optional[bytes] = None
    ) -> tuple[CryptoEngine, bytes]:
        """Derive a 32-byte key from a passphrase using Argon2id."""
        raw_pass = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        used_salt = salt if salt is not None else os.urandom(16)
        derived = derive_key_argon2id(raw_pass, salt=used_salt)
        return cls(derived), used_salt

    @classmethod
    def resolve_master_key(
        cls,
        passphrase_or_key: Optional[bytes] = None,
        data_dir: Optional[str | Path] = None,
    ) -> bytes:
        """Resolve a 32-byte master key from explicit bytes, OS keyring, or 0o600 keyfile."""
        base_dir = Path(data_dir) if data_dir is not None else Path(paths.get_default_data_dir())
        if passphrase_or_key is not None:
            if len(passphrase_or_key) == 32:
                return passphrase_or_key
            salt_path = base_dir / "keys" / "db_salt.bin"
            if salt_path.exists():
                salt = salt_path.read_bytes()
            else:
                salt_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                salt = os.urandom(16)
                fd = os.open(str(salt_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
                try:
                    os.write(fd, salt)
                finally:
                    os.close(fd)
            return derive_key_argon2id(passphrase_or_key, salt=salt)

        keyring_key = _try_keyring_get("ether-core", "master-db-key")
        if keyring_key and len(keyring_key) == 32:
            return keyring_key

        key_path = base_dir / "keys" / "db_master.key"
        if key_path.exists():
            return key_path.read_bytes()

        new_key = os.urandom(32)
        if _try_keyring_set("ether-core", "master-db-key", new_key):
            return new_key

        key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(key_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            os.write(fd, new_key)
        finally:
            os.close(fd)
        return new_key

    def encrypt_field(self, plaintext: str, aad: bytes = b"ether-field-v1") -> str:
        """Encrypt a string field using ChaCha20-Poly1305 with a 12-byte random nonce and key ID."""
        if plaintext.startswith(ENC_PREFIX):
            return plaintext
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return f"{ENC_PREFIX}{self._key_id}:{base64.b64encode(nonce + ct).decode('ascii')}"

    def decrypt_field(self, value: str, aad: bytes = b"ether-field-v1") -> str:
        """Decrypt a ChaCha20-Poly1305 encrypted field; supports key-versioned and legacy payloads."""
        if not isinstance(value, str) or not value.startswith(ENC_PREFIX):
            return value
        body = value[len(ENC_PREFIX) :]
        aead = self._aead
        if ":" in body:
            kid, b64_payload = body.split(":", 1)
            if kid != self._key_id and kid in self._previous_aeads:
                aead = self._previous_aeads[kid]
        else:
            b64_payload = body
        raw = base64.b64decode(b64_payload.encode("ascii"))
        nonce, ct = raw[:12], raw[12:]
        pt = aead.decrypt(nonce, ct, aad)
        return pt.decode("utf-8")

    def rotate_key(self, new_key: bytes) -> None:
        """Rotate to a new 32-byte encryption key, retaining the previous key for decryption."""
        if len(new_key) != 32:
            raise ValueError("CryptoEngine requires a 32-byte encryption key.")
        self._previous_aeads[self._key_id] = self._aead
        zeroize_bytes(self._key_buf)
        self._key_buf = bytearray(new_key)
        self._aead = ChaCha20Poly1305(bytes(self._key_buf))
        self._key_id = hashlib.sha256(bytes(self._key_buf)).hexdigest()[:12]

    def reencrypt_field(self, value: str, aad: bytes = b"ether-field-v1") -> str:
        """Re-encrypt an encrypted field under the currently active key ID."""
        if not isinstance(value, str) or not value.startswith(ENC_PREFIX):
            return value
        plaintext = self.decrypt_field(value, aad=aad)
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return f"{ENC_PREFIX}{self._key_id}:{base64.b64encode(nonce + ct).decode('ascii')}"

    @staticmethod
    def redact_finding_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive credential fields before exporting or sharing findings."""
        out = dict(data)
        for key in SENSITIVE_CREDENTIAL_FIELDS:
            if key in out and out[key]:
                out[key] = "[REDACTED]"
        return out

    def encrypt_finding_data(self, schema_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive credential/raw fields before SQLite persistence."""
        out = dict(data)
        aad = schema_type.encode("utf-8")
        if schema_type == "credential.found" or any(k in out for k in SENSITIVE_CREDENTIAL_FIELDS):
            for key in SENSITIVE_CREDENTIAL_FIELDS:
                val = out.get(key)
                if isinstance(val, str) and val and not val.startswith(ENC_PREFIX):
                    out[key] = self.encrypt_field(val, aad=aad)
        raw_val = out.get("raw_data")
        if isinstance(raw_val, str) and raw_val and not raw_val.startswith(ENC_PREFIX):
            out["raw_data"] = self.encrypt_field(raw_val, aad=aad)
        return out

    def decrypt_finding_data(self, schema_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive fields after reading from SQLite, enforcing credential TTL expiry."""
        out = dict(data)
        aad = schema_type.encode("utf-8")
        for key in (*SENSITIVE_CREDENTIAL_FIELDS, "raw_data"):
            val = out.get(key)
            if isinstance(val, str) and val.startswith(ENC_PREFIX):
                out[key] = self.decrypt_field(val, aad=aad)
        if is_credential_expired(out):
            for key in SENSITIVE_CREDENTIAL_FIELDS:
                if key in out and out[key]:
                    out[key] = "[EXPIRED]"
            out["expired"] = True
        return out

    def close(self) -> None:
        """Zeroize the in-memory key buffer."""
        zeroize_bytes(self._key_buf)

    @classmethod
    def open_encrypted_store(
        cls,
        db_path: Path | str,
        passphrase_or_key: Optional[bytes] = None,
        data_dir: Optional[Path] = None,
    ) -> Any:
        """Open a GraphStore protected by CryptoEngine (and SQLCipher if available)."""
        from ether.graph.store import GraphStore

        key = cls.resolve_master_key(passphrase_or_key=passphrase_or_key, data_dir=data_dir)
        engine = cls(key=key)
        store = GraphStore(
            str(db_path),
            crypto_engine=engine,
            sqlcipher_enabled=_has_sqlcipher(),
        )
        return store
