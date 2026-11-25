"""Format-level stream recovery primitives for truncated or malformed scanner outputs."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Union


def salvage_json_objects(buffer: Union[str, bytes]) -> List[Dict[str, Any]]:
    """Scan damaged, truncated, or concatenated JSON buffers and extract all valid dict objects.

    Handles truncated array buffers (e.g. `[{"a":1},{"b":2},{"partial":...`)
    and concatenated JSON streams without raising JSONDecodeError.
    """
    if isinstance(buffer, bytes):
        text = buffer.decode("utf-8", errors="replace")
    else:
        text = str(buffer)

    text = text.strip()
    if not text:
        return []

    results: List[Dict[str, Any]] = []

    # First, try standard complete JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return [parsed]
        elif isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    except Exception:
        pass

    # Incremental decoder scan
    decoder = json.JSONDecoder()
    pos = 0
    length = len(text)

    while pos < length:
        # Find next opening brace
        next_brace = text.find("{", pos)
        if next_brace == -1:
            break
        try:
            obj, end_pos = decoder.raw_decode(text, idx=next_brace)
            if isinstance(obj, dict):
                results.append(obj)
            pos = end_pos
        except Exception:
            # Skip past this brace and continue scanning
            pos = next_brace + 1

    return results


def salvage_ndjson_lines(buffer: Union[str, bytes]) -> List[Dict[str, Any]]:
    """Extract valid JSON objects from newline-delimited JSON streams, skipping corrupted lines."""
    if isinstance(buffer, bytes):
        text = buffer.decode("utf-8", errors="replace")
    else:
        text = str(buffer)

    results: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                results.append(parsed)
        except Exception:
            continue
    return results


def salvage_xml_elements(buffer: Union[str, bytes], tag: str) -> List[str]:
    """Extract complete <tag>...</tag> fragments from damaged or truncated XML streams."""
    if isinstance(buffer, bytes):
        text = buffer.decode("utf-8", errors="replace")
    else:
        text = str(buffer)

    pattern = re.compile(rf"(<{tag}\b[^>]*>.*?</{tag}>)", re.DOTALL)
    return pattern.findall(text)


class StreamRecoveryEngine:
    """Format-level recovery supervisor for salvaging intelligence from interrupted tool runs."""

    @staticmethod
    def salvage_json_objects(buffer: Union[str, bytes]) -> List[Dict[str, Any]]:
        return salvage_json_objects(buffer)

    @staticmethod
    def salvage_ndjson_lines(buffer: Union[str, bytes]) -> List[Dict[str, Any]]:
        return salvage_ndjson_lines(buffer)

    @staticmethod
    def salvage_xml_elements(buffer: Union[str, bytes], tag: str) -> List[str]:
        return salvage_xml_elements(buffer, tag)
