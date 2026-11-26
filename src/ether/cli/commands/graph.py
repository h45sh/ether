"""Handlers for 'ether graph' subcommands."""

import getpass
import json
import os
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table
from ether.common.crypto import decrypt_bytes, encrypt_bytes
from ether.schemas.base import BaseFinding

_CREDENTIAL_SECRET_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "hash",
        "ntlm_hash",
        "private_key",
        "passphrase",
        "credential",
    }
)


def _mask_secret_dict(mapping: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of mapping with sensitive credential keys masked."""
    masked = dict(mapping)
    for key in _CREDENTIAL_SECRET_KEYS:
        if key in masked and masked[key] not in (None, ""):
            masked[key] = "********"
    return masked


def _mask_credential_node(node: dict[str, Any], unmask: bool) -> dict[str, Any]:
    """Hydrate pik/data on a node dict and mask credential secrets unless unmask is True."""
    item = dict(node)
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

    if not unmask and item.get("schema_type") == "credential.found":
        if isinstance(item.get("pik"), dict):
            item["pik"] = _mask_secret_dict(item["pik"])
            if "pik_json" in item:
                item["pik_json"] = json.dumps(item["pik"])
        if isinstance(item.get("data"), dict):
            item["data"] = _mask_secret_dict(item["data"])
            if "data_json" in item:
                item["data_json"] = json.dumps(item["data"])

    return item


async def handle_graph_list_nodes(args: Any, context: CliContext) -> int:
    """List finding nodes recorded in an investigation session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required. Run 'ether session list' to find session IDs.")
        return EXIT_RUNTIME_ERROR

    schema_type = getattr(args, "type", None)
    include_stale = bool(getattr(args, "include_stale", False))
    unmask = bool(getattr(args, "unmask", False))

    async with context.open_store() as store:
        if schema_type:
            nodes = await store.query(
                schema_type, session_id=session_id, include_stale=include_stale
            )
        else:
            nodes = await store.get_all_nodes(session_id, include_stale=include_stale)

    parsed_nodes = [_mask_credential_node(n, unmask=unmask) for n in nodes]

    if context.is_json:
        print_json(parsed_nodes)
        return EXIT_SUCCESS

    headers = ["NODE ID", "SCHEMA TYPE", "TARGET / PIK", "STATUS"]
    rows = []
    for item in parsed_nodes:
        pik = item.get("pik")
        if isinstance(pik, dict):
            pik_display = ", ".join(f"{k}={v}" for k, v in pik.items())
        else:
            pik_display = str(item.get("pik_json", ""))
        if len(pik_display) > 40:
            pik_display = pik_display[:37] + "..."
        rows.append(
            [
                item.get("id", "")[:12],
                item.get("schema_type", ""),
                pik_display,
                item.get("status", "confirmed"),
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
            encrypted_payload = encrypt_bytes(raw_json.encode("utf-8"), passphrase or "")
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(output_path, flags, 0o600)
            with open(fd, "wb") as f:
                f.write(encrypted_payload)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(raw_json)

        if context.is_json:
            print_json(
                {
                    "session_id": session_id,
                    "output_path": output_path,
                    "nodes_count": len(nodes),
                    "edges_count": len(edges),
                    "encrypted": encrypt,
                }
            )
        else:
            suffix = "encrypted archive " if encrypt else ""
            print(
                f"[+] Exported {len(nodes)} nodes and {len(edges)} edges to {suffix}'{output_path}'"
            )
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
                node_finding = BaseFinding(
                    schema_type=n["schema_type"],
                    pik=n["pik"],
                    data=n.get("data", {}),
                    status=n.get("status", "confirmed"),
                )
                findings_to_upsert.append(node_finding)
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


async def handle_graph_prune(args: Any, context: CliContext) -> int:
    """Prune decayed stale nodes older than max_age_seconds from a session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    max_age = int(getattr(args, "max_age", 604800))

    async with context.open_store() as store:
        pruned_count = await store.prune_stale_nodes(session_id, max_age_seconds=max_age)

    if context.is_json:
        print_json({"session_id": session_id, "pruned_nodes": pruned_count})
    else:
        print(f"[+] Successfully pruned {pruned_count} stale node(s) from session '{session_id}'.")

    return EXIT_SUCCESS


async def handle_graph_search(args: Any, context: CliContext) -> int:
    """Perform offline semantic search against finding entities in an investigation session."""
    session_id = getattr(args, "session_id", None)
    query = getattr(args, "query", None)
    if not session_id or not query:
        print_error(
            "session_id and query are required. Usage: ether graph search <session_id> '<query>'"
        )
        return EXIT_RUNTIME_ERROR

    limit = int(getattr(args, "limit", 10) or 10)
    min_score = float(getattr(args, "min_score", 0.0) or 0.0)
    schema_type = getattr(args, "type", None)

    async with context.open_store() as store:
        results = await store.semantic_search(
            session_id=session_id,
            query=query,
            limit=limit,
            min_score=min_score,
            schema_type=schema_type,
        )

    if context.is_json:
        print_json(results)
        return EXIT_SUCCESS

    if not results:
        print(f"No semantic matches found for query '{query}' in session {session_id}.")
        return EXIT_SUCCESS

    headers = ["SCORE", "NODE ID", "SCHEMA TYPE", "TARGET / SUMMARY"]
    rows = []
    for r in results:
        score = f"{r.get('similarity', 0.0):.3f}"
        nid = r.get("id", "")[:12]
        st = r.get("schema_type", "")
        summary = ""
        pik = r.get("pik") or {}
        data = r.get("data") or {}
        if st == "network.host":
            summary = pik.get("ip") or data.get("ip", "")
        elif st == "network.service":
            summary = f"{data.get('service_name', 'svc')} on {pik.get('host_ip')}:{pik.get('port')}"
            if data.get("banner"):
                summary += f" ({data['banner']})"
        elif st == "web.endpoint":
            summary = pik.get("url") or data.get("url", "")
            if data.get("title"):
                summary += f" [{data['title']}]"
        elif st == "web.technology":
            summary = f"{data.get('technology_name')} on {pik.get('url')}"
        elif st == "vulnerability.found":
            summary = (
                f"{pik.get('vuln_id')} ({data.get('severity', 'UNKNOWN')}): {data.get('title', '')}"
            )
        elif st == "credential.found":
            summary = f"User '{pik.get('username')}' in context '{pik.get('context')}'"
        else:
            summary = ", ".join(f"{k}={v}" for k, v in pik.items())

        if len(summary) > 60:
            summary = summary[:57] + "..."
        rows.append([score, nid, st, summary])

    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_graph_belief(args: Any, context: CliContext) -> int:
    """Inspect and evaluate Bayesian beliefs and deception state for a session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    evaluate = bool(getattr(args, "evaluate", False))

    async with context.open_store() as store:
        if evaluate:
            from ether.graph.analytics import GraphAnalyticsEngine

            beliefs = await GraphAnalyticsEngine.evaluate_and_persist(store, session_id)
        else:
            beliefs = await store.list_node_beliefs(session_id)
            if not beliefs:
                from ether.graph.analytics import GraphAnalyticsEngine

                beliefs = await GraphAnalyticsEngine.evaluate_and_persist(store, session_id)

    if context.is_json:
        print_json(beliefs)
        return EXIT_SUCCESS

    if not beliefs:
        print("No findings or belief records found for session.")
        return EXIT_SUCCESS

    headers = ["NODE ID", "CONFIDENCE", "HONEYPOT", "TARPIT", "INDICATORS"]
    rows = []
    for b in beliefs:
        rows.append(
            [
                b["node_id"][:12] + "...",
                f"{b['confidence']:.2f}",
                "YES" if b["is_honeypot"] else "no",
                "YES" if b["is_tarpit"] else "no",
                ", ".join(b["indicators"]) if b["indicators"] else "none",
            ]
        )
    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_graph_attack_path(args: Any, context: CliContext) -> int:
    """Compute shortest directed attack path between two entity IDs."""
    from ether.graph.analytics import GraphAnalyticsEngine

    session_id = getattr(args, "session_id", None)
    source_id = getattr(args, "source_id", None)
    target_id = getattr(args, "target_id", None)
    if not session_id or not source_id or not target_id:
        print_error("session_id, source_id, and target_id are required.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)

    analytics = GraphAnalyticsEngine(nodes, edges)
    path = analytics.find_shortest_attack_path(source_id, target_id)

    if context.is_json:
        print_json(
            {
                "session_id": session_id,
                "source_id": source_id,
                "target_id": target_id,
                "found": path is not None,
                "path": path or [],
            }
        )
        return EXIT_SUCCESS

    if not path:
        print(f"[-] No directed attack path found from '{source_id}' to '{target_id}'.")
        return EXIT_SUCCESS

    print(f"[+] Shortest Attack Path ({len(path)} hops):")
    for idx, nid in enumerate(path):
        print(f"  {idx + 1}. {nid}")
    return EXIT_SUCCESS


async def handle_graph_blast_radius(args: Any, context: CliContext) -> int:
    """Calculate compromise blast radius for a compromised entity node."""
    from ether.graph.analytics import GraphAnalyticsEngine

    session_id = getattr(args, "session_id", None)
    node_id = getattr(args, "node_id", None)
    max_depth = int(getattr(args, "max_depth", 10))
    if not session_id or not node_id:
        print_error("session_id and node_id are required.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)

    analytics = GraphAnalyticsEngine(nodes, edges)
    radius_set = analytics.calculate_blast_radius(node_id, max_depth=max_depth)
    affected = sorted(list(radius_set))

    if context.is_json:
        print_json(
            {
                "session_id": session_id,
                "compromised_node_id": node_id,
                "max_depth": max_depth,
                "total_affected": len(affected),
                "affected_entity_ids": affected,
            }
        )
        return EXIT_SUCCESS

    print(
        f"[+] Compromise Blast Radius for '{node_id}' (max_depth={max_depth}): {len(affected)} entity(ies)"
    )
    for nid in affected:
        print(f"  - {nid}")
    return EXIT_SUCCESS


async def handle_graph_crown_jewels(args: Any, context: CliContext) -> int:
    """Identify critical crown-jewel assets and topological choke points."""
    from ether.graph.analytics import GraphAnalyticsEngine

    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("session_id is required.")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)

    analytics = GraphAnalyticsEngine(nodes, edges)
    jewels = analytics.identify_critical_assets()

    if context.is_json:
        print_json(
            {
                "session_id": session_id,
                "total_critical": len(jewels),
                "crown_jewels": jewels,
            }
        )
        return EXIT_SUCCESS

    if not jewels:
        print("No critical crown-jewel assets identified in session.")
        return EXIT_SUCCESS

    headers = ["NODE ID", "SCHEMA TYPE", "STATUS"]
    rows = [
        [j.get("id", "")[:12] + "...", j.get("schema_type", ""), j.get("status", "")]
        for j in jewels
    ]
    print_table(headers, rows)
    return EXIT_SUCCESS
