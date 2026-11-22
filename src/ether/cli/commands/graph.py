"""Handlers for 'ether graph' subcommands."""

import getpass
import json
import os
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table
from ether.common.crypto import decrypt_bytes, encrypt_bytes
from ether.schemas.base import BaseFinding


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
        rows.append(
            [
                n.get("id", "")[:12],
                n.get("schema_type", ""),
                pik_display,
                n.get("status", "confirmed"),
            ]
        )

    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_graph_export(args: Any, context: CliContext) -> int:
    """Export session finding graph and relations to JSON or encrypted archive."""
    session_id = getattr(args, "session_id", None)
    output_path = getattr(args, "output", None)
    encrypt = bool(getattr(args, "encrypt", False))
    passphrase = getattr(args, "passphrase", None)

    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    if encrypt and not passphrase:
        try:
            passphrase = getpass.getpass("Enter archive encryption passphrase: ")
        except Exception:
            print_error("Encryption requested but no passphrase supplied.")
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

    raw_json = json.dumps(export_data, indent=2)

    if output_path:
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        if encrypt:
            encrypted_payload = encrypt_bytes(raw_json.encode("utf-8"), passphrase)
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(output_path, flags, 0o600)
            with open(fd, "wb") as f:
                f.write(encrypted_payload)
            print(
                f"[+] Exported {len(nodes)} nodes and {len(edges)} edges to encrypted archive '{output_path}'"
            )
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(raw_json)
            print(f"[+] Exported {len(nodes)} nodes and {len(edges)} edges to '{output_path}'")
    else:
        if encrypt:
            print_error("Encrypted export requires an output file path (-o <path>).")
            return EXIT_RUNTIME_ERROR
        print_json(export_data)

    return EXIT_SUCCESS


async def handle_graph_import(args: Any, context: CliContext) -> int:
    """Import findings from a JSON file or encrypted archive into an investigation session."""
    input_path = getattr(args, "input", None)
    session_id = getattr(args, "session_id", None)
    passphrase = getattr(args, "passphrase", None)

    if not input_path or not os.path.exists(input_path):
        print_error(f"Input file '{input_path}' not found.")
        return EXIT_RUNTIME_ERROR

    with open(input_path, "rb") as f:
        file_bytes = f.read()

    # Detect if encrypted archive (starts with ETHER_SECURE_ARC)
    if file_bytes.startswith(b"ETHER_SECURE_ARC"):
        if not passphrase:
            try:
                passphrase = getpass.getpass("Enter archive decryption passphrase: ")
            except Exception:
                print_error("Encrypted archive detected but no passphrase supplied.")
                return EXIT_RUNTIME_ERROR

        try:
            plaintext = decrypt_bytes(file_bytes, passphrase)
            data = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            print_error(f"Failed to decrypt archive: {exc}")
            return EXIT_RUNTIME_ERROR
    else:
        try:
            data = json.loads(file_bytes.decode("utf-8"))
        except Exception as exc:
            print_error(f"Failed to parse JSON input file: {exc}")
            return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        if not session_id:
            # Use session_id from export data or create a new session
            orig_id = data.get("session_id")
            if orig_id:
                session_id = orig_id
                # Ensure session exists
                existing = await store.get_session(session_id)
                if not existing:
                    ws_id, _ = await store.get_or_create_default_session()
                    await store.create_session(
                        ws_id, f"Imported {session_id[:8]}", session_id=session_id
                    )
            else:
                ws_id, sess_id = await store.get_or_create_default_session()
                session_id = sess_id

        imported_count = 0
        findings_to_upsert = []
        for n in data.get("nodes", []):
            try:
                f = BaseFinding(
                    schema_type=n["schema_type"],
                    pik=n["pik"],
                    data=n.get("data", {}),
                    status=n.get("status", "confirmed"),
                )
                findings_to_upsert.append(f)
            except Exception:
                continue

        if findings_to_upsert:
            await store.upsert_findings_batch(session_id, findings_to_upsert)
            imported_count = len(findings_to_upsert)

    if context.is_json:
        print_json({"session_id": session_id, "imported_nodes": imported_count})
    else:
        print(f"[+] Successfully imported {imported_count} nodes into session '{session_id}'")

    return EXIT_SUCCESS
