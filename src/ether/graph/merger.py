"""Deep module encapsulating node attribute merging and database row hydration."""

from __future__ import annotations

import json
from typing import Any, Dict


def hydrate_node_row(row: Any) -> Dict[str, Any]:
    """Convert a SQLite node row to a dict with hydrated 'pik' and 'data' dicts."""
    item = dict(row)
    for json_col, dict_key in (("pik_json", "pik"), ("data_json", "data")):
        raw = item.get(json_col)
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
                item[dict_key] = parsed if isinstance(parsed, dict) else {}
            except Exception:
                item[dict_key] = {}
        elif dict_key not in item:
            item[dict_key] = {}
    return item


_hydrate_node_row = hydrate_node_row


class NodeAttributeMerger:
    """Encapsulates non-destructive attribute merging across multiple tool findings."""

    @staticmethod
    def merge_node_data(
        existing_data: Dict[str, Any], incoming_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge incoming finding attributes non-destructively into existing node data."""
        merged = dict(existing_data)
        for key, val in incoming_data.items():
            if val is None or val == "" or val == []:
                continue
            if key not in merged or merged[key] is None or merged[key] == "":
                merged[key] = val
            elif isinstance(merged[key], list) and isinstance(val, list):
                # Union lists preserving insertion order without duplicates
                seen = set()
                combined = []
                for item in merged[key] + val:
                    item_key = (
                        json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
                    )
                    if item_key not in seen:
                        seen.add(item_key)
                        combined.append(item)
                merged[key] = combined
            elif isinstance(merged[key], dict) and isinstance(val, dict):
                merged[key] = NodeAttributeMerger.merge_node_data(merged[key], val)
            else:
                # Prefer newer non-empty attribute value
                merged[key] = val
        return merged
