"""Handlers for 'ether session' subcommands."""

from typing import Any

from ether.cli.context import EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


async def handle_session_list(args: Any, context: CliContext) -> int:
    """List investigation sessions in the database."""
    workspace_id = getattr(args, "workspace_id", None)

    async with context.open_store() as store:
        if workspace_id:
            sessions = await store.list_sessions(workspace_id)
        else:
            sessions = await store.list_all_sessions()

    if context.is_json:
        print_json(sessions)
        return EXIT_SUCCESS

    headers = ["SESSION ID", "WORKSPACE ID", "NAME", "CREATED AT"]
    rows = [
        [
            s.get("id", ""),
            s.get("workspace_id", ""),
            s.get("name", ""),
            str(s.get("created_at", ""))[:19],
        ]
        for s in sessions
    ]
    print_table(headers, rows)
    return EXIT_SUCCESS


async def handle_session_create(args: Any, context: CliContext) -> int:
    """Create a new investigation session."""
    name = getattr(args, "name", "New Session")
    workspace_id = getattr(args, "workspace_id", None)

    async with context.open_store() as store:
        if not workspace_id:
            ws_id, sess_id = await store.get_or_create_default_session()
            workspace_id = ws_id

        sess_id = await store.create_session(workspace_id, name)

    if context.is_json:
        print_json({"session_id": sess_id, "workspace_id": workspace_id, "name": name})
    else:
        print(f"[+] Created session '{name}' (ID: {sess_id}) in workspace '{workspace_id}'")

    return EXIT_SUCCESS


async def handle_session_verify_audit(args: Any, context: CliContext) -> int:
    """Verify cryptographic chain of custody and file hashes for a session's audit manifest."""
    from ether.common.forensic_log import ForensicLogManager

    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("Missing required session_id.")
        return 1

    is_valid, records = ForensicLogManager.verify_session_audit(
        session_id, data_dir=context.data_dir
    )
    if context.is_json:
        print_json({"session_id": session_id, "valid": is_valid, "entries": records})
        return EXIT_SUCCESS if is_valid else 1

    if not records:
        print(f"[-] No audit manifest found for session '{session_id}'.")
        return EXIT_SUCCESS

    headers = ["INDEX", "ACTION ID", "TOOL", "LOG FILE", "CHAIN", "FILE", "STATUS"]
    rows = []
    for r in records:
        rows.append(
            [
                str(r["index"]),
                str(r["action_id"])[:8],
                str(r["tool"]),
                str(r["log_file"]),
                "PASS" if r["hash_chain_valid"] else "FAIL",
                "PASS" if r["file_hash_valid"] else "FAIL",
                "VALID" if r["valid"] else "TAMPERED",
            ]
        )
    print_table(headers, rows)
    if is_valid:
        print(f"[+] Cryptographic audit chain verified: All {len(records)} entries intact.")
        return EXIT_SUCCESS
    else:
        print("[!] Forensic audit verification FAILED: Tampering or corruption detected.")
        return 1


async def handle_session_close(args: Any, context: CliContext) -> int:
    """Seal a session as forensically closed and compress raw log spools to .log.gz."""
    from ether.common.forensic_log import ForensicLogManager

    session_id = getattr(args, "session_id", None)
    if not session_id:
        print_error("Missing required session_id.")
        return 1

    async with context.open_store() as store:
        await store.close_session(session_id)

    compressed = ForensicLogManager.compress_session_logs(session_id, data_dir=context.data_dir)
    compressed_count = len(compressed)

    if context.is_json:
        print_json(
            {
                "session_id": session_id,
                "status": "CLOSED",
                "compressed_logs": compressed_count,
            }
        )
    else:
        print(
            f"[+] Forensically sealed session '{session_id}' "
            f"(compressed {compressed_count} log spool(s) to .log.gz)."
        )
    return EXIT_SUCCESS
