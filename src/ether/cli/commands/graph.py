"""Handlers for 'ether graph' subcommands."""

import json
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


async def handle_graph_list_nodes(args: Any, context: CliContext) -> int:
    """List finding nodes recorded in an investigation session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required. Run 'ether session list' to find session IDs.")
        return EXIT_RUNTIME_ERROR

    schema_type = getattr(args, "type", None)

    async with context.open_store() as store:
        if schema_type:
            nodes = await store.query(schema_type, session_id=session_id)
        else:
            nodes = await store.get_all_nodes(session_id)

    if context.is_json:
        parsed_nodes = []
        for n in nodes:
            item = dict(n)
            if "pik_json" in item and isinstance(item["pik_json"], str):
                try:
                    item["pik"] = json.loads(item["pik_json"])
                except Exception:
                    pass
            if "data_json" in item and isinstance(item["data_json"], str):
                try:
                    item["data"] = json.loads(item["data_json"])
                except Exception:
                    pass
            parsed_nodes.append(item)
        print_json(parsed_nodes)
        return EXIT_SUCCESS

    headers = ["NODE ID", "SCHEMA TYPE", "TARGET / PIK", "STATUS"]
    rows = []
    for n in nodes:
        pik_display = ""
        try:
            pik = json.loads(n.get("pik_json", "{}"))
            pik_display = ", ".join(f"{k}={v}" for k, v in pik.items())
        except Exception:
            pik_display = n.get("pik_json", "")
        if len(pik_display) > 40:
            pik_display = pik_display[:37] + "..."
        rows.append([n.get("id", "")[:12], n.get("schema_type", ""), pik_display, n.get("status", "confirmed")])

    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_graph_export(args: Any, context: CliContext) -> int:
    """Export session finding graph and relations to JSON or copy to output SQLite DB."""
    session_id = getattr(args, "session_id", None)
    output_path = getattr(args, "output", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)

    export_data = {
        "session_id": session_id,
        "nodes": [
            {
                "id": n["id"],
                "schema_type": n["schema_type"],
                "pik": json.loads(n["pik_json"]) if "pik_json" in n else {},
                "data": json.loads(n["data_json"]) if "data_json" in n else {},
                "status": n.get("status", "confirmed"),
            }
            for n in nodes
        ],
        "edges": [
            {
                "source_id": e["source_id"],
                "target_id": e["target_id"],
                "relation_type": e.get("relation_type", "relates_to"),
            }
            for e in edges
        ],
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"[+] Exported {len(nodes)} nodes and {len(edges)} edges to '{output_path}'")
    else:
        print_json(export_data)

    return EXIT_SUCCESS
