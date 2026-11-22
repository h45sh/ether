"""CLI argument parsing, subcommand routing, and execution dispatch for Ether."""

import argparse
import asyncio
import sys
from typing import List, Optional

from ether import __version__
from ether.cli.commands.doctor import handle_doctor
from ether.cli.commands.graph import (
    handle_graph_export,
    handle_graph_import,
    handle_graph_list_nodes,
)
from ether.cli.commands.logs import handle_logs
from ether.cli.commands.run import handle_run
from ether.cli.commands.session import handle_session_create, handle_session_list
from ether.cli.commands.telemetry import handle_telemetry_diff, handle_telemetry_snapshot
from ether.cli.commands.tool import handle_tool_info, handle_tool_list
from ether.cli.context import (
    EXIT_RUNTIME_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE_ERROR,
    CliContext,
)
from ether.cli.formatters import print_error


def build_parser() -> argparse.ArgumentParser:
    """Construct the Ether CLI argument parser with noun-verb subcommands."""
    common_options = argparse.ArgumentParser(add_help=False)
    common_options.add_argument(
        "--data-dir",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Path to Ether unified data directory (default: ~/.ether or $ETHER_DATA_DIR)",
    )
    common_options.add_argument(
        "--db",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Path to SQLite database (default: ~/.ether/ether.db)",
    )
    common_options.add_argument(
        "--tools",
        metavar="DIR",
        default=argparse.SUPPRESS,
        help="Path to tool adapters directory (default: bundled tools/)",
    )
    common_options.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output in machine-readable JSON format",
    )
    common_options.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debug logging to stderr",
    )
    common_options.add_argument(
        "--policy",
        choices=["safe", "unrestricted"],
        default="safe",
        help="Execution gateway policy mode (default: safe)",
    )

    parser = argparse.ArgumentParser(
        prog="ether",
        description="Ether: Headless reactive process supervisor and deterministic graph telemetry engine.",
        parents=[common_options],
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"Ether v{__version__}",
        help="Show Ether engine version and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. doctor
    subparsers.add_parser(
        "doctor",
        parents=[common_options],
        help="Run comprehensive system, database, and tool diagnostics",
    )

    # 2. tool
    tool_parser = subparsers.add_parser(
        "tool",
        parents=[common_options],
        help="Inspect registered security tool adapters",
    )
    tool_subs = tool_parser.add_subparsers(dest="tool_action")
    tool_subs.add_parser("list", parents=[common_options], help="List all available tools")
    tool_info_p = tool_subs.add_parser("info", parents=[common_options], help="Show details for a tool")
    tool_info_p.add_argument("name", help="Name of the tool to inspect")

    # 3. run
    run_parser = subparsers.add_parser(
        "run",
        parents=[common_options],
        help="Supervise and execute a tool scan action",
    )
    run_parser.add_argument("tool", help="Tool to execute (e.g. nmap, subfinder, gobuster)")
    run_parser.add_argument("target", help="Target IP, hostname, URL, or CIDR")
    run_parser.add_argument(
        "--flags",
        nargs=argparse.REMAINDER,
        default=[],
        help="Extra flags to pass to the tool binary",
    )
    run_parser.add_argument("-s", "--session-id", dest="session_id", help="Session ID to record findings into")

    # 4. session
    session_parser = subparsers.add_parser(
        "session",
        parents=[common_options],
        help="Manage investigation sessions",
    )
    session_subs = session_parser.add_subparsers(dest="session_action")
    sess_list_p = session_subs.add_parser("list", parents=[common_options], help="List sessions")
    sess_list_p.add_argument("-w", "--workspace-id", dest="workspace_id", help="Filter by workspace ID")
    sess_create_p = session_subs.add_parser("create", parents=[common_options], help="Create a new session")
    sess_create_p.add_argument("name", nargs="?", default="New Session", help="Session display name")
    sess_create_p.add_argument("-w", "--workspace-id", dest="workspace_id", help="Target workspace ID")

    # 5. graph
    graph_parser = subparsers.add_parser(
        "graph",
        parents=[common_options],
        help="Query and export deterministic entity graphs",
    )
    graph_subs = graph_parser.add_subparsers(dest="graph_action")
    nodes_p = graph_subs.add_parser("list-nodes", parents=[common_options], help="List finding nodes")
    nodes_p.add_argument("session_id", help="Session ID to inspect")
    nodes_p.add_argument("-t", "--type", dest="type", help="Filter by schema_type (e.g. network.host)")

    export_p = graph_subs.add_parser("export", parents=[common_options], help="Export session graph")
    export_p.add_argument("session_id", help="Session ID to export")
    export_p.add_argument("-o", "--output", dest="output", help="Output JSON or archive file path")
    export_p.add_argument("--encrypt", action="store_true", help="Encrypt export using AES-256-GCM + Argon2id")
    export_p.add_argument("--passphrase", dest="passphrase", help="Passphrase for encryption")

    import_p = graph_subs.add_parser(
        "import", parents=[common_options], help="Import findings from JSON or encrypted archive"
    )
    import_p.add_argument("input", help="Path to input JSON or encrypted archive (.enc)")
    import_p.add_argument("-s", "--session-id", dest="session_id", help="Target session ID")
    import_p.add_argument("--passphrase", dest="passphrase", help="Decryption passphrase")

    # 6. telemetry
    telemetry_parser = subparsers.add_parser(
        "telemetry",
        parents=[common_options],
        help="Agent telemetry protocol: knapsack snapshots and zero-token diffs",
    )
    telemetry_subs = telemetry_parser.add_subparsers(dest="telemetry_action")
    snap_p = telemetry_subs.add_parser("snapshot", parents=[common_options], help="Compile token-budgeted snapshot")
    snap_p.add_argument("session_id", help="Session ID")
    snap_p.add_argument("--max-tokens", dest="max_tokens", type=int, default=4000, help="Max token budget")
    snap_p.add_argument("--entity-id", dest="entity_id", help="Selected entity node ID")

    diff_p = telemetry_subs.add_parser("diff", parents=[common_options], help="Compute graph diff since baseline")
    diff_p.add_argument("session_id", help="Session ID")
    diff_p.add_argument("--baseline", dest="baseline", required=True, help="Baseline timestamp")

    # 7. logs
    logs_parser = subparsers.add_parser(
        "logs",
        parents=[common_options],
        help="Inspect system runtime logs and crash traces",
    )
    logs_parser.add_argument("--limit", type=int, default=50, help="Number of lines to tail")
    logs_parser.add_argument("--crashes", action="store_true", help="Show recent unhandled crash summary")

    return parser


def _run_coroutine(coro):
    """Run an async coroutine, safely handling environments where an event loop is already running."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return EXIT_SUCCESS

    context = CliContext.from_args(args)

    try:
        if args.subcommand == "doctor":
            return _run_coroutine(handle_doctor(args, context))

        elif args.subcommand == "tool":
            if args.tool_action == "info":
                return handle_tool_info(args, context)
            return handle_tool_list(args, context)

        elif args.subcommand == "run":
            return _run_coroutine(handle_run(args, context))

        elif args.subcommand == "session":
            if args.session_action == "create":
                return _run_coroutine(handle_session_create(args, context))
            return _run_coroutine(handle_session_list(args, context))

        elif args.subcommand == "graph":
            if args.graph_action == "export":
                return _run_coroutine(handle_graph_export(args, context))
            elif args.graph_action == "import":
                return _run_coroutine(handle_graph_import(args, context))
            return _run_coroutine(handle_graph_list_nodes(args, context))

        elif args.subcommand == "telemetry":
            if args.telemetry_action == "diff":
                return _run_coroutine(handle_telemetry_diff(args, context))
            return _run_coroutine(handle_telemetry_snapshot(args, context))

        elif args.subcommand == "logs":
            return handle_logs(args, context)

        else:
            parser.print_help()
            return EXIT_USAGE_ERROR

    except KeyboardInterrupt:
        print("\n[!] Ether operation interrupted by user.", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    except Exception as exc:
        if context.verbose:
            import traceback

            traceback.print_exc(file=sys.stderr)
        else:
            print_error(str(exc))
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())
