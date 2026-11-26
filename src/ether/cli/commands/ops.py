"""Handlers for high-velocity operational CLI commands: status, ps, kill, report."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any, Dict, List

from ether import paths
from ether.cli.commands.graph import _mask_credential_node
from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


async def handle_status(args: Any, context: CliContext) -> int:
    """Display one-glance operational status for the active or specified session."""
    session_id_arg = getattr(args, "session_id", None)
    async with context.open_store() as store:
        session_id = await context.resolve_session_id(store, session_id_arg)
        sess = await store.get_session(session_id) or {}
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)
        events = await store.timeline.query_timeline(session_id, limit=20)

    by_type = Counter(n.get("schema_type", "unknown") for n in nodes)
    sev_counts: Counter[str] = Counter()
    for n in nodes:
        if n.get("schema_type", "").startswith("vuln"):
            try:
                data = json.loads(n.get("data_json") or "{}")
            except Exception:
                data = {}
            sev = str(data.get("severity", "unknown")).lower()
            sev_counts[sev] += 1

    active_jobs = [e for e in events if str(e.get("status", "")).lower() in ("running", "pending")]
    summary = {
        "session_id": session_id,
        "session_name": sess.get("name", ""),
        "status": "closed" if sess.get("closed") else "active",
        "policy": context.policy.value,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "nodes_by_type": dict(sorted(by_type.items())),
        "vulnerabilities_by_severity": dict(sorted(sev_counts.items())),
        "active_jobs": len(active_jobs),
        "recent_actions": len(events),
    }

    if context.is_json:
        print_json(summary)
        return EXIT_SUCCESS

    print(
        f"Session: {summary['session_id']} ({summary['session_name']}) "
        f"[{summary['status'].upper()} | policy={summary['policy']}]"
    )
    print(
        f"Graph:   {summary['total_nodes']} nodes, {summary['total_edges']} edges | "
        f"Active jobs: {summary['active_jobs']} | Recent actions: {summary['recent_actions']}"
    )
    if by_type:
        print("\nNodes by type:")
        for stype, cnt in sorted(by_type.items()):
            print(f"  - {stype}: {cnt}")
    if sev_counts:
        print("\nVulnerabilities by severity:")
        for sev, cnt in sorted(sev_counts.items()):
            print(f"  - {sev}: {cnt}")
    return EXIT_SUCCESS


async def handle_ps(args: Any, context: CliContext) -> int:
    """List running and recent actions in the active or specified session."""
    session_id_arg = getattr(args, "session_id", None)
    limit = int(getattr(args, "limit", 25))

    async with context.open_store() as store:
        session_id = await context.resolve_session_id(store, session_id_arg)
        events = await store.timeline.query_timeline(session_id, limit=limit)

    if context.is_json:
        print_json({"session_id": session_id, "total": len(events), "actions": events})
        return EXIT_SUCCESS

    if not events:
        print(f"No recorded actions for session '{session_id}'.")
        return EXIT_SUCCESS

    headers = ["EVENT ID", "ACTION ID", "TOOL", "STATUS", "TIMESTAMP"]
    rows = []
    for e in events:
        try:
            act = json.loads(e.get("action_payload") or "{}")
        except Exception:
            act = {}
        try:
            res = json.loads(e.get("result_payload") or "{}")
        except Exception:
            res = {}
        rows.append(
            [
                str(e.get("id", "")),
                str(act.get("action_id", ""))[:12],
                str(act.get("tool_name", "")),
                str(res.get("status", e.get("schema_type", ""))),
                str(e.get("timestamp", ""))[:19],
            ]
        )
    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_kill(args: Any, context: CliContext) -> int:
    """Mark a running or orphaned action as aborted/closed."""
    action_id = getattr(args, "action_id", None)
    session_id_arg = getattr(args, "session_id", None)
    if not action_id:
        print_error("action_id is required. Usage: ether kill <action_id>")
        return EXIT_RUNTIME_ERROR

    async with context.open_store() as store:
        session_id = await context.resolve_session_id(store, session_id_arg)
        await store.timeline.mark_event_closed(action_id, session_id=session_id)

    if context.is_json:
        print_json({"action_id": action_id, "session_id": session_id, "aborted": True})
    else:
        print(f"[+] Marked action '{action_id}' closed/aborted in session '{session_id}'.")
    return EXIT_SUCCESS


async def handle_report(args: Any, context: CliContext) -> int:
    """Compile a Markdown or JSON engagement report from the session graph."""
    session_id_arg = getattr(args, "session_id", None)
    fmt = str(getattr(args, "format", "md")).lower()
    out_path = getattr(args, "output", None)
    unmask = bool(getattr(args, "unmask", False))

    async with context.open_store() as store:
        session_id = await context.resolve_session_id(store, session_id_arg)
        sess = await store.get_session(session_id) or {}
        nodes = await store.get_all_nodes(session_id)
        edges = await store.get_all_edges(session_id)

    masked_nodes = [_mask_credential_node(n, unmask=unmask) for n in nodes]
    payload: Dict[str, Any] = {
        "session_id": session_id,
        "session_name": sess.get("name", ""),
        "status": "closed" if sess.get("closed") else "active",
        "total_nodes": len(masked_nodes),
        "total_edges": len(edges),
        "nodes": masked_nodes,
        "edges": edges,
    }

    if context.is_json or fmt == "json":
        rendered = json.dumps(payload, indent=2, default=str)
    else:
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for n in masked_nodes:
            by_type.setdefault(n.get("schema_type", "unknown"), []).append(n)
        lines: List[str] = [
            f"# Ether Engagement Report — {sess.get('name', session_id)}",
            "",
            f"- **Session ID:** `{session_id}`",
            f"- **Status:** `{payload['status']}`",
            f"- **Total Nodes:** {len(masked_nodes)}",
            f"- **Total Edges:** {len(edges)}",
            "",
        ]
        for stype in sorted(by_type):
            items = by_type[stype]
            lines.append(f"## {stype} ({len(items)})")
            for item in items:
                pik = item.get("pik", {})
                pik_str = (
                    ", ".join(f"{k}={v}" for k, v in pik.items())
                    if isinstance(pik, dict)
                    else str(pik)
                )
                lines.append(f"- `{item.get('id', '')[:12]}` — {pik_str}")
            lines.append("")
        rendered = "\n".join(lines)

    if out_path:
        abs_out = os.path.abspath(os.path.expanduser(out_path))
        paths.atomic_create_file(abs_out, rendered + "\n")
        if context.is_json:
            print_json({"session_id": session_id, "output": abs_out, "format": fmt})
        else:
            print(f"[+] Report written to {abs_out}")
    elif context.is_json or fmt == "json":
        print(rendered)
    else:
        print(rendered)

    return EXIT_SUCCESS
