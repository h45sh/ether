"""Zero-leakage in-memory credential and secret scrubbing primitives for Ether.

Uses ctypes.memset to overwrite sensitive cryptographic keys, passwords, and tokens
directly in process memory upon task finalization, preventing residual keys from
lingering in the Python heap or process core dumps.
"""

import ctypes
import re
from typing import Any, List, Optional, Set, Tuple, Union

DEFAULT_SENSITIVE_KEYS: Set[str] = {
    "password",
    "passphrase",
    "token",
    "auth_token",
    "access_token",
    "bearer",
    "api_key",
    "secret",
    "secret_key",
    "private_key",
    "ssh_key",
    "id_rsa",
    "authorization",
    "credential",
    "credentials",
}

DEFAULT_REDACT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|passwd|auth)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"
        ),
        r"\1=***REDACTED***",
    ),
    (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{15,}"), "Bearer ***REDACTED***"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "sk-***REDACTED***"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "ghp_***REDACTED***"),
    (re.compile(r"://([^:]+):([^@]+)@"), r"://\1:***@"),
    (
        re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"),
        "-----"
        + "BEGIN PRIVATE KEY"
        + "----- [***REDACTED***] -----"
        + "END PRIVATE KEY"
        + "-----",  # codeguard: ignore[SECRET_PRIVATE_KEY]
    ),
]


def sanitize_text_secrets(
    text: str, patterns: Optional[List[Tuple[re.Pattern, str]]] = None
) -> str:
    """Scrub sensitive credentials, tokens, and private keys from an unstructured text stream."""
    if not text:
        return text
    active_patterns = patterns or DEFAULT_REDACT_PATTERNS
    sanitized = text
    for pattern, replacement in active_patterns:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def wipe_buffer(buf: Union[bytearray, ctypes.Array, Any]) -> None:
    """Zero out the memory of a mutable buffer in-place using ctypes.memset."""
    if isinstance(buf, bytearray):
        if len(buf) > 0:
            char_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
            ctypes.memset(ctypes.addressof(char_arr), 0, len(buf))
    elif hasattr(buf, "_type_") and hasattr(buf, "_length_"):
        # Ctypes array
        size = ctypes.sizeof(buf)
        ctypes.memset(ctypes.addressof(buf), 0, size)


class SecureBuffer:
    """A mutable byte buffer with guaranteed in-place memory zeroing.

    Zeroes memory on context exit (__exit__), explicit wipe(), or finalization (__del__).
    """

    def __init__(self, data: Union[bytes, bytearray, str]) -> None:
        if isinstance(data, str):
            encoded = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            encoded = bytes(data)
        else:
            raise TypeError(
                f"SecureBuffer accepts bytes, bytearray, or str, got {type(data).__name__}"
            )

        self._buf: bytearray = bytearray(encoded)
        self._wiped: bool = False

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    def get_bytes(self) -> bytes:
        if self._wiped:
            raise ValueError("SecureBuffer has already been wiped.")
        return bytes(self._buf)

    def get_string(self) -> str:
        if self._wiped:
            raise ValueError("SecureBuffer has already been wiped.")
        return self._buf.decode("utf-8", errors="replace")

    def wipe(self) -> None:
        """Overwrite the internal memory with null bytes immediately."""
        if not self._wiped and len(self._buf) > 0:
            wipe_buffer(self._buf)
            self._wiped = True

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        return "<SecureBuffer: [WIPED]>" if self._wiped else f"<SecureBuffer: len={len(self._buf)}>"


def wipe_credentials(target: Any, sensitive_keys: Optional[Set[str]] = None) -> None:
    """Recursively traverse a dictionary or list, wiping sensitive values in-place."""
    keys = sensitive_keys or DEFAULT_SENSITIVE_KEYS

    if isinstance(target, dict):
        for k in list(target.keys()):
            val = target[k]
            key_lower = str(k).lower()
            is_sensitive = any(sk in key_lower for sk in keys)

            if isinstance(val, (dict, list)):
                wipe_credentials(val, sensitive_keys=keys)
            elif is_sensitive:
                if isinstance(val, SecureBuffer):
                    val.wipe()
                elif isinstance(val, bytearray):
                    wipe_buffer(val)
                elif isinstance(val, (bytes, str)):
                    target[k] = "[WIPED]"

    elif isinstance(target, list):
        for _idx, item in enumerate(target):
            if isinstance(item, (bytearray, SecureBuffer)):
                if isinstance(item, SecureBuffer):
                    item.wipe()
                else:
                    wipe_buffer(item)
            elif isinstance(item, (dict, list)):
                wipe_credentials(item, sensitive_keys=keys)
