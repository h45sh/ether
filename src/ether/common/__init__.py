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

__all__ = [
    "ANSI_ESCAPE_RE",
    "BloomFilter",
    "CTF_FLAG_RE",
    "DisjointSet",
    "IPRadixTrie",
    "MinHash",
    "dfa_strip_ansi",
    "extract_ctf_flags",
    "knapsack_01",
    "strip_ansi",
    "strip_scanner_noise",
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


def strip_scanner_noise(raw_text: str) -> str:
    """Filter out repetitive scanner banner headers, ASCII art, and progress bars."""
    cleaned_text = ANSI_ESCAPE_RE.sub("", raw_text)
    lines = cleaned_text.splitlines()
    cleaned = []
    noise_prefixes = (
        "Starting Nmap",
        "Nmap done:",
        "Gobuster v",
        "by OJ Reeves",
        "[-] Loaded",
        "[-] Target:",
        "[-] Flags:",
        "[-] Method:",
        "[-] Wordlist:",
        "[-] Extensions:",
        "[-] Mode:",
        "[-] Threads:",
        "[-] Timeout:",
        "- Nikto v",
        "+ Target IP:",
        "+ Target Hostname:",
        "+ Target Port:",
        "+ Start Time:",
        "+ End Time:",
        "+ 0 host(s) tested",
        ":: Method :",
        ":: URL :",
        ":: Wordlist :",
        ":: Header :",
        ":: Output :",
        ":: Follow :",
        "[INF] Current nuclei version:",
        "[INF] New templates added in nuclei-templates",
        "[INF] Loading templates...",
        "[INF] Using",
        "[INF] Target:",
        "[INF] Templates cluster",
        "[INF] Scan stats:",
        "[INF] Enumerating subdomains for",
        "% This is the RIPE Database",
        "% Rights restricted",
        "# whois.arin.net",
        "NOTICE: The expiration date",
        "___",
        "---",
        "===",
        "***",
    )
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if all(c in "=-_*~#./\\ " for c in stripped) and len(stripped) > 4:
            continue
        if "Progress:" in stripped or "Stats:" in stripped or "ETA:" in stripped:
            continue
        normalized = re.sub(r"^\[[\+\*\-\!]\]\s*", "", stripped)
        if any(stripped.startswith(p) or normalized.startswith(p) for p in noise_prefixes):
            continue
        if sum(1 for c in stripped if c in "/\\|`_") > len(stripped) * 0.5 and len(stripped) > 5:
            continue
        cleaned.append(stripped)

    return "\n".join(cleaned[-60:]) if cleaned else raw_text[-1500:]
