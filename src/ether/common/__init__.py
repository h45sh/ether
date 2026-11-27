"""Common shared algorithmic and string primitives for Ether."""

import re
from typing import List

from ether.common.algorithms import (
    BloomFilter,
    DisjointSet,
    IPRadixTrie,
    MinHash,
    knapsack_01,
)
from ether.common.crypto import (
    CryptoError,
    InvalidArchiveFormatError,
    InvalidPassphraseError,
    TamperedArchiveError,
    decrypt_bytes,
    decrypt_file,
    derive_key_argon2id,
    encrypt_bytes,
    encrypt_file,
)
from ether.common.exceptions import (
    EtherError,
    ExecutionErrorCategory,
    PolicyViolationError,
)
from ether.common.secure_memory import SecureBuffer, wipe_buffer, wipe_credentials

__all__ = [
    "ANSI_ESCAPE_RE",
    "AuditRecord",
    "BloomFilter",
    "CTF_FLAG_RE",
    "CryptoError",
    "DisjointSet",
    "EtherError",
    "ExecutionErrorCategory",
    "ForensicLogManager",
    "IPRadixTrie",
    "InvalidArchiveFormatError",
    "InvalidPassphraseError",
    "LogSpooler",
    "MinHash",
    "PolicyViolationError",
    "SecureBuffer",
    "TamperedArchiveError",
    "decrypt_bytes",
    "decrypt_file",
    "derive_key_argon2id",
    "dfa_strip_ansi",
    "encrypt_bytes",
    "encrypt_file",
    "extract_ctf_flags",
    "knapsack_01",
    "sanitize_untrusted_output",
    "strip_ansi",
    "wipe_buffer",
    "wipe_credentials",
]

ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CTF_FLAG_RE = re.compile(r"(?:flag|FLAG|ctf|CTF|htb|HTB|thm|THM)\{[A-Za-z0-9_!@#$%^&*+=?.-]+\}")

_STATE_TEXT = 0
_STATE_ESC = 1
_STATE_CSI = 2
_STATE_OSC = 3
_STATE_OSC_ESC = 4


def strip_ansi(text: str) -> str:
    """Strip ANSI color codes, cursor sequences, and OSC title strings in strict linear time O(N)
    using an unrolled state machine without regex engine overhead.
    """
    if not text or "\x1b" not in text:
        return text

    out: List[str] = []
    state = _STATE_TEXT
    chunk_start = 0

    for i, ch in enumerate(text):
        if state == _STATE_TEXT:
            if ch == "\x1b":
                if i > chunk_start:
                    out.append(text[chunk_start:i])
                state = _STATE_ESC
        elif state == _STATE_ESC:
            if ch == "[":
                state = _STATE_CSI
            elif ch == "]":
                state = _STATE_OSC
            else:
                state = _STATE_TEXT
                chunk_start = i + 1
        elif state == _STATE_CSI:
            ord_c = ord(ch)
            if 0x40 <= ord_c <= 0x7E:
                state = _STATE_TEXT
                chunk_start = i + 1
        elif state == _STATE_OSC:
            if ch == "\x07":
                state = _STATE_TEXT
                chunk_start = i + 1
            elif ch == "\x1b":
                state = _STATE_OSC_ESC
        elif state == _STATE_OSC_ESC:
            if ch == "\\":
                state = _STATE_TEXT
                chunk_start = i + 1
            else:
                state = _STATE_OSC

    if state == _STATE_TEXT and chunk_start < len(text):
        out.append(text[chunk_start:])

    return "".join(out)


dfa_strip_ansi = strip_ansi


def extract_ctf_flags(text: str) -> List[str]:
    """Extract distinct CTF flag strings from text in order of appearance."""
    if not text:
        return []
    flags: List[str] = []
    seen = set()
    for match in CTF_FLAG_RE.finditer(text):
        f = match.group(0)
        if f not in seen:
            seen.add(f)
            flags.append(f)
    return flags


def sanitize_untrusted_output(raw_text: str) -> str:
    """Wrap untrusted scanner output in protective boundary tags and neutralize breakout attempts."""
    if not raw_text:
        return "<untrusted_scan_output>\n</untrusted_scan_output>"
    neutralized = re.sub(
        r"<\s*(/?)\s*untrusted_scan_output\b([^>]*)>",
        lambda m: rf"<\{m.group(1)}untrusted_scan_output{m.group(2)}>",
        raw_text,
        flags=re.IGNORECASE,
    )
    return f"<untrusted_scan_output>\n{neutralized}\n</untrusted_scan_output>"


from ether.common.forensic_log import AuditRecord, ForensicLogManager, LogSpooler
