"""Handlers for 'ether session' subcommands."""

from typing import Any

from ether.cli.context import EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_json, print_table


async def handle_session_list(args: Any, context: CliContext) -> int:
    """List investigation sessions in the database."""
    workspace_id = getattr(args, "workspace_id", None)

    async with context.open_store() as store:
        if workspace_id:
            sessions = await store.list_sessions(workspace_id)
        else:
            # Query all sessions across all workspaces
            async with store.connection() as db:
                import aiosqlite

                db.row_factory = aiosqlite.Row
                cursor = await db.execute("SELECT * FROM sessions ORDER BY created_at DESC")
                rows = await cursor.fetchall()
                sessions = [dict(r) for r in rows]

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
            ws_id, sess_id = await store.get_or_create_learning_sandbox()
            workspace_id = ws_id

        sess_id = await store.create_session(workspace_id, name)

    if context.is_json:
        print_json({"session_id": sess_id, "workspace_id": workspace_id, "name": name})
    else:
        print(f"[+] Created session '{name}' (ID: {sess_id}) in workspace '{workspace_id}'")

    return EXIT_SUCCESS
