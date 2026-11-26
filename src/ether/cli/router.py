"""CLI argument parsing, subcommand routing, and execution dispatch for Ether."""

import argparse
import asyncio
import sys
from typing import List, Optional

from ether import __version__
from ether.cli.commands.config import handle_config_path, handle_config_show
from ether.cli.commands.doctor import handle_doctor
from ether.cli.commands.drift import handle_drift_audit, handle_drift_export_baseline
from ether.cli.commands.graph import (
    handle_graph_attack_path,
    handle_graph_belief,
    handle_graph_blast_radius,
    handle_graph_crown_jewels,
    handle_graph_export,
    handle_graph_import,
    handle_graph_list_nodes,
    handle_graph_prune,
    handle_graph_search,
)
from ether.cli.commands.logs import handle_logs
from ether.cli.commands.mcp import handle_mcp
from ether.cli.commands.pipeline import handle_pipeline_run
from ether.cli.commands.run import handle_run
from ether.cli.commands.session import (
    handle_session_close,
    handle_session_create,
    handle_session_list,
    handle_session_verify_audit,
)
from ether.cli.commands.telemetry import (
    handle_telemetry_diff,
    handle_telemetry_health,
    handle_telemetry_snapshot,
)
from ether.cli.commands.tool import handle_tool_info, handle_tool_list, handle_tool_search
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
        "-j",
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Output in machine-readable JSON format",
    )
    common_options.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose debug logging to stderr",
    )
    common_options.add_argument(
        "--policy",
        choices=["safe", "unrestricted"],
        default=argparse.SUPPRESS,
        help="Execution gateway policy mode (default: safe)",
    )
    common_options.add_argument(
        "--config",
        metavar="PATH",
        default=argparse.SUPPRESS,
        help="Path to Ether config.toml (default: ~/.ether/config.toml)",
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
    tool_search_p = tool_subs.add_parser(
        "search", parents=[common_options], help="Search tools by keyword or schema"
    )
    tool_search_p.add_argument("query", nargs="?", default=None, help="Keyword to search")
    tool_search_p.add_argument("--accepts", default=None, help="Filter by input schema")
    tool_search_p.add_argument("--produces", default=None, help="Filter by output schema")
    tool_info_p = tool_subs.add_parser(
        "info", parents=[common_options], help="Show details for a tool"
    )
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
        "--profile",
        default=None,
        help="Preset flag profile from manifest.toml (e.g. fast, standard, deep)",
    )
    run_parser.add_argument(
        "--flags",
        default="",
        type=str,
        help="Extra flags to pass to the tool binary",
    )
    run_parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Override execution timeout in seconds (default: settings.execution.default_timeout_sec)",
    )
    run_parser.add_argument(
        "-s", "--session-id", dest="session_id", help="Session ID to record findings into"
    )

    # 4. session
    session_parser = subparsers.add_parser(
        "session",
        parents=[common_options],
        help="Manage investigation sessions",
    )
    session_subs = session_parser.add_subparsers(dest="session_action")
    sess_list_p = session_subs.add_parser("list", parents=[common_options], help="List sessions")
    sess_list_p.add_argument(
        "-w", "--workspace-id", dest="workspace_id", help="Filter by workspace ID"
    )
    sess_create_p = session_subs.add_parser(
        "create", parents=[common_options], help="Create a new session"
    )
    sess_create_p.add_argument(
        "name", nargs="?", default="New Session", help="Session display name"
    )
    sess_create_p.add_argument(
        "-w", "--workspace-id", dest="workspace_id", help="Target workspace ID"
    )
    sess_verify_p = session_subs.add_parser(
        "verify-audit",
        parents=[common_options],
        help="Verify cryptographic audit chain and log file integrity for a session",
    )
    sess_verify_p.add_argument("session_id", help="Session ID to verify")
    sess_close_p = session_subs.add_parser(
        "close",
        parents=[common_options],
        help="Forensically seal a session and compress raw log spools to .log.gz",
    )
    sess_close_p.add_argument("session_id", help="Session ID to seal and compress")

    # 5. graph
    graph_parser = subparsers.add_parser(
        "graph",
        parents=[common_options],
        help="Query and export deterministic entity graphs",
    )
    graph_subs = graph_parser.add_subparsers(dest="graph_action")
    nodes_p = graph_subs.add_parser(
        "list-nodes", parents=[common_options], help="List finding nodes"
    )
    nodes_p.add_argument("session_id", help="Session ID to inspect")
    nodes_p.add_argument(
        "-t", "--type", dest="type", help="Filter by schema_type (e.g. network.host)"
    )
    nodes_p.add_argument(
        "--include-stale", action="store_true", help="Include decayed stale nodes in listing"
    )
    nodes_p.add_argument(
        "--unmask", action="store_true", help="Display sensitive credential attributes in plaintext"
    )

    prune_p = graph_subs.add_parser(
        "prune", parents=[common_options], help="Prune decayed stale nodes from session graph"
    )
    prune_p.add_argument("session_id", help="Session ID to prune")
    prune_p.add_argument(
        "--max-age",
        dest="max_age",
        type=int,
        default=604800,
        help="Max age in seconds for stale nodes (default: 604800 / 7 days)",
    )

    export_p = graph_subs.add_parser(
        "export", parents=[common_options], help="Export session graph"
    )
    export_p.add_argument("session_id", help="Session ID to export")
    export_p.add_argument("-o", "--output", dest="output", help="Output JSON or archive file path")
    export_p.add_argument(
        "--encrypt", action="store_true", help="Encrypt export using AES-256-GCM + Argon2id"
    )
    export_p.add_argument("--passphrase", dest="passphrase", help="Passphrase for encryption")

    import_p = graph_subs.add_parser(
        "import", parents=[common_options], help="Import findings from JSON or encrypted archive"
    )
    import_p.add_argument("input", help="Path to input JSON or encrypted archive (.enc)")
    import_p.add_argument("-s", "--session-id", dest="session_id", help="Target session ID")
    import_p.add_argument("--passphrase", dest="passphrase", help="Decryption passphrase")

    search_p = graph_subs.add_parser(
        "search", parents=[common_options], help="Semantic similarity search over finding entities"
    )
    search_p.add_argument("session_id", help="Session ID to search")
    search_p.add_argument("query", help="Natural language query string")
    search_p.add_argument(
        "-l",
        "--limit",
        dest="limit",
        type=int,
        default=10,
        help="Maximum findings to return (default: 10)",
    )
    search_p.add_argument(
        "-m",
        "--min-score",
        dest="min_score",
        type=float,
        default=0.0,
        help="Minimum cosine similarity score (default: 0.0)",
    )
    search_p.add_argument(
        "-t", "--type", dest="type", help="Filter by schema_type (e.g. network.service)"
    )
    search_p.add_argument(
        "--unmask", action="store_true", help="Display sensitive credential attributes in plaintext"
    )

    belief_p = graph_subs.add_parser(
        "belief",
        parents=[common_options],
        help="Inspect Bayesian belief scores and honeypot/tarpit status",
    )
    belief_p.add_argument("session_id", help="Session ID to inspect")
    belief_p.add_argument(
        "--evaluate",
        action="store_true",
        help="Re-run Bayesian deception analysis before displaying",
    )

    attack_path_p = graph_subs.add_parser(
        "attack-path",
        parents=[common_options],
        help="Compute shortest directed attack path between entities",
    )
    attack_path_p.add_argument("session_id", help="Session ID")
    attack_path_p.add_argument("source_id", help="Origin entity ID")
    attack_path_p.add_argument("target_id", help="Destination entity ID")

    blast_p = graph_subs.add_parser(
        "blast-radius",
        parents=[common_options],
        help="Calculate compromise blast radius for a node",
    )
    blast_p.add_argument("session_id", help="Session ID")
    blast_p.add_argument("node_id", help="Compromised entity ID")
    blast_p.add_argument(
        "--max-depth", type=int, default=10, help="Maximum hop depth (default: 10)"
    )

    jewels_p = graph_subs.add_parser(
        "crown-jewels",
        parents=[common_options],
        help="Identify critical crown-jewel assets in a session",
    )
    jewels_p.add_argument("session_id", help="Session ID")

    # 6. telemetry
    telemetry_parser = subparsers.add_parser(
        "telemetry",
        parents=[common_options],
        help="Agent telemetry protocol: knapsack snapshots and zero-token diffs",
    )
    telemetry_subs = telemetry_parser.add_subparsers(dest="telemetry_action")
    snap_p = telemetry_subs.add_parser(
        "snapshot", parents=[common_options], help="Compile token-budgeted snapshot"
    )
    snap_p.add_argument("session_id", help="Session ID")
    snap_p.add_argument(
        "--max-tokens", dest="max_tokens", type=int, default=4000, help="Max token budget"
    )
    snap_p.add_argument(
        "--budget", dest="budget", type=int, default=None, help="Alias for --max-tokens"
    )
    snap_p.add_argument("--entity-id", dest="entity_id", help="Selected entity node ID")

    diff_p = telemetry_subs.add_parser(
        "diff", parents=[common_options], help="Compute graph diff by action ID or since baseline"
    )
    diff_p.add_argument("session_id", help="Session ID")
    diff_p.add_argument("--action-id", dest="action_id", help="Action ID to diff")
    diff_p.add_argument("--baseline", dest="baseline", help="Baseline timestamp")

    health_p = telemetry_subs.add_parser(
        "health", parents=[common_options], help="Inspect runtime health, memory, FDs, and metrics"
    )
    health_p.add_argument(
        "--prometheus", action="store_true", help="Output metrics in Prometheus text format"
    )

    # 7. logs
    logs_parser = subparsers.add_parser(
        "logs",
        parents=[common_options],
        help="Inspect system runtime logs and crash traces",
    )
    logs_parser.add_argument("--limit", type=int, default=50, help="Number of lines to tail")
    logs_parser.add_argument(
        "--crashes", action="store_true", help="Show recent unhandled crash summary"
    )
    logs_parser.add_argument(
        "--prune",
        action="store_true",
        help="Enforce log retention quota and compress historical logs",
    )
    logs_parser.add_argument(
        "--max-disk-mb",
        type=int,
        default=1000,
        help="Maximum log directory size in MB (default: 1000)",
    )
    logs_parser.add_argument(
        "--max-age-days",
        type=int,
        default=30,
        help="Maximum age for log retention in days (default: 30)",
    )
    logs_parser.add_argument(
        "--include-forensic",
        action="store_true",
        help="Force compression and pruning of audit_manifest-tracked forensic logs",
    )

    # 8. mcp
    mcp_parser = subparsers.add_parser(
        "mcp",
        parents=[common_options],
        help="Launch Native Model Context Protocol (MCP) server for AI agents",
    )
    mcp_parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP protocol transport (default: stdio)",
    )
    mcp_parser.add_argument(
        "-s",
        "--session-id",
        dest="session_id",
        help="Bind MCP server to specific investigation session ID",
    )
    mcp_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )
    mcp_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for SSE transport (default: 127.0.0.1)",
    )
    mcp_parser.add_argument(
        "--auth-token",
        dest="auth_token",
        default=None,
        help="Bearer authentication token for MCP SSE endpoints (or ETHER_MCP_AUTH_TOKEN env var)",
    )

    # 9. pipeline
    pipeline_parser = subparsers.add_parser(
        "pipeline",
        parents=[common_options],
        help="Execute chained tool pipeline DAG (e.g. 'subfinder | dnspython | http_probe')",
    )
    pipeline_parser.add_argument("expression", help="Pipeline expression string")
    pipeline_parser.add_argument(
        "-s",
        "--session",
        dest="session",
        help="Session ID to associate findings with",
    )

    # 10. drift
    drift_parser = subparsers.add_parser(
        "drift",
        parents=[common_options],
        help="Audit architectural drift against baseline ground truth",
    )
    drift_subs = drift_parser.add_subparsers(dest="drift_action")
    drift_export_p = drift_subs.add_parser(
        "export-baseline",
        parents=[common_options],
        help="Export session graph as ground-truth baseline JSON",
    )
    drift_export_p.add_argument("session_id", help="Session ID to export")
    drift_export_p.add_argument(
        "-o", "--out", dest="out", help="Output file path for baseline JSON"
    )

    drift_audit_p = drift_subs.add_parser(
        "audit",
        parents=[common_options],
        help="Audit session graph against baseline JSON",
    )
    drift_audit_p.add_argument("session_id", help="Session ID to audit")
    drift_audit_p.add_argument(
        "-b",
        "--baseline",
        required=True,
        dest="baseline",
        help="Path to ground-truth baseline JSON file",
    )
    drift_audit_p.add_argument(
        "-m",
        "--mode",
        choices=["topology", "strict"],
        default="topology",
        help="Evaluation mode (default: topology)",
    )
    drift_audit_p.add_argument(
        "-r",
        "--record",
        action="store_true",
        help="Record AuditDrift findings into session graph",
    )

    # 11. config
    config_parser = subparsers.add_parser(
        "config",
        parents=[common_options],
        help="Inspect unified Ether configuration and config.toml path",
    )
    config_subs = config_parser.add_subparsers(dest="config_action")
    config_show_p = config_subs.add_parser(
        "show", parents=[common_options], help="Display resolved EtherSettings"
    )
    config_show_p.add_argument(
        "--unmask",
        action="store_true",
        help="Include unmasked auth tokens in output",
    )
    config_subs.add_parser("path", parents=[common_options], help="Print active config.toml path")

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


def normalize_cli_args(argv: Optional[List[str]] = None) -> List[str]:
    """Pre-normalize CLI argument vector for 100% positional and keyword parameter symmetry."""
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)

    if not argv:
        return argv

    subcmd_idx = -1
    subcommands = {
        "doctor",
        "tool",
        "run",
        "session",
        "graph",
        "telemetry",
        "logs",
        "mcp",
        "pipeline",
        "drift",
    }

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in subcommands:
            subcmd_idx = i
            break
        if arg in ("--data-dir", "--db", "--tools", "--policy"):
            i += 2
            continue
        i += 1

    if subcmd_idx == -1:
        return argv

    subcmd = argv[subcmd_idx]
    prefix = argv[: subcmd_idx + 1]
    rest = argv[subcmd_idx + 1 :]

    # Hoist boolean flags (-j, --json, -v, --verbose) appearing before sub-actions to preserve symmetry
    if subcmd in ("session", "tool", "graph", "telemetry", "drift") and rest:
        hoisted_flags = []
        cleaned_rest = []
        for t in rest:
            if t in ("-j", "--json", "-v", "--verbose"):
                hoisted_flags.append(t)
            else:
                cleaned_rest.append(t)
        rest = cleaned_rest + hoisted_flags

    if subcmd == "run":
        new_rest = []
        tool_val = None
        target_val = None
        idx = 0
        while idx < len(rest):
            token = rest[idx]
            if token == "--flags":
                new_rest.extend(rest[idx:])
                break
            elif token == "--tool":
                if idx + 1 < len(rest):
                    tool_val = rest[idx + 1]
                    idx += 2
                    continue
            elif token.startswith("--tool="):
                tool_val = token.split("=", 1)[1]
                idx += 1
                continue
            elif token == "--target":
                if idx + 1 < len(rest):
                    target_val = rest[idx + 1]
                    idx += 2
                    continue
            elif token.startswith("--target="):
                target_val = token.split("=", 1)[1]
                idx += 1
                continue
            new_rest.append(token)
            idx += 1

        pos_args = []
        opt_args = []
        j = 0
        while j < len(new_rest):
            t = new_rest[j]
            if t.startswith("-"):
                opt_args.extend(new_rest[j:])
                break
            pos_args.append(t)
            j += 1

        final_pos = list(pos_args)
        if len(final_pos) == 0 and tool_val:
            final_pos.append(tool_val)
        if len(final_pos) == 1 and target_val:
            final_pos.append(target_val)

        return prefix + final_pos + opt_args

    elif subcmd == "session":
        if rest and rest[0] == "list":
            sub_prefix = [rest[0]]
            sub_rest = rest[1:]
            if len(sub_rest) == 1 and not sub_rest[0].startswith("-"):
                return prefix + sub_prefix + ["--workspace-id", sub_rest[0]]
            return prefix + rest
        elif rest and rest[0] == "create":
            sub_prefix = [rest[0]]
            sub_rest = rest[1:]
            new_sub_rest = []
            name_val = None
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token == "--name":
                    if idx + 1 < len(sub_rest):
                        name_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--name="):
                    name_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            if name_val:
                return prefix + sub_prefix + [name_val] + new_sub_rest
            return prefix + rest
        elif rest and rest[0] in ("verify-audit", "close"):
            sub_action = rest[0]
            sub_prefix = [sub_action]
            sub_rest = rest[1:]
            sess_val = None
            new_sub_rest = []
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token in ("-s", "--session-id", "--session"):
                    if idx + 1 < len(sub_rest):
                        sess_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--session-id=") or token.startswith("--session="):
                    sess_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            if sess_val:
                return prefix + sub_prefix + [sess_val] + new_sub_rest
            return prefix + rest

    elif subcmd == "tool":
        if rest and rest[0] == "info":
            sub_prefix = [rest[0]]
            sub_rest = rest[1:]
            name_val = None
            new_sub_rest = []
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token in ("--name", "--tool"):
                    if idx + 1 < len(sub_rest):
                        name_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--name=") or token.startswith("--tool="):
                    name_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            if name_val:
                return prefix + sub_prefix + [name_val] + new_sub_rest
            return prefix + rest

    elif subcmd == "graph":
        if rest and rest[0] in ("list-nodes", "prune", "search", "belief", "crown-jewels"):
            sub_action = rest[0]
            sub_prefix = [sub_action]
            sub_rest = rest[1:]
            sess_val = None
            new_sub_rest = []
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token in ("-s", "--session-id", "--session"):
                    if idx + 1 < len(sub_rest):
                        sess_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--session-id=") or token.startswith("--session="):
                    sess_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            if sess_val:
                return prefix + sub_prefix + [sess_val] + new_sub_rest
            return prefix + rest
        elif rest and rest[0] == "export":
            sub_prefix = [rest[0]]
            sub_rest = rest[1:]
            sess_val = None
            out_val = None
            new_sub_rest = []
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token in ("-s", "--session-id", "--session"):
                    if idx + 1 < len(sub_rest):
                        sess_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--session-id=") or token.startswith("--session="):
                    sess_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                elif token in ("-o", "--output"):
                    if idx + 1 < len(sub_rest):
                        out_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--output="):
                    out_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            pos = [t for t in new_sub_rest if not t.startswith("-")]
            opts = [t for t in new_sub_rest if t.startswith("-")]
            if sess_val and out_val:
                return prefix + sub_prefix + [sess_val] + opts + ["-o", out_val]
            elif sess_val and len(pos) == 1:
                return prefix + sub_prefix + [sess_val] + opts + ["-o", pos[0]]
            elif len(pos) == 2 and not out_val:
                return prefix + sub_prefix + [pos[0]] + opts + ["-o", pos[1]]
            elif sess_val:
                return prefix + sub_prefix + [sess_val] + new_sub_rest
            return prefix + rest

    elif subcmd == "drift":
        if rest and rest[0] in ("export-baseline", "audit"):
            sub_action = rest[0]
            sub_prefix = [sub_action]
            sub_rest = rest[1:]
            sess_val = None
            new_sub_rest = []
            idx = 0
            while idx < len(sub_rest):
                token = sub_rest[idx]
                if token in ("-s", "--session-id", "--session"):
                    if idx + 1 < len(sub_rest):
                        sess_val = sub_rest[idx + 1]
                        idx += 2
                        continue
                elif token.startswith("--session-id=") or token.startswith("--session="):
                    sess_val = token.split("=", 1)[1]
                    idx += 1
                    continue
                new_sub_rest.append(token)
                idx += 1
            if sess_val:
                return prefix + sub_prefix + [sess_val] + new_sub_rest
            return prefix + rest

    return prefix + rest


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    if argv is None:
        argv = sys.argv[1:]
    normalized_argv = normalize_cli_args(argv)
    # Rewrite `--flags <val>` to `--flags=<val>` so argparse never treats `-p 80` or `-v` as a CLI option
    safe_argv: List[str] = []
    idx = 0
    while idx < len(normalized_argv):
        tok = normalized_argv[idx]
        if tok == "--flags" and idx + 1 < len(normalized_argv):
            safe_argv.append(f"--flags={normalized_argv[idx + 1]}")
            idx += 2
        else:
            safe_argv.append(tok)
            idx += 1
    parser = build_parser()
    args = parser.parse_args(safe_argv)

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
            elif args.tool_action == "search":
                return handle_tool_search(args, context)
            return handle_tool_list(args, context)

        elif args.subcommand == "run":
            return _run_coroutine(handle_run(args, context))

        elif args.subcommand == "session":
            if args.session_action == "create":
                return _run_coroutine(handle_session_create(args, context))
            elif args.session_action == "verify-audit":
                return _run_coroutine(handle_session_verify_audit(args, context))
            elif args.session_action == "close":
                return _run_coroutine(handle_session_close(args, context))
            return _run_coroutine(handle_session_list(args, context))

        elif args.subcommand == "graph":
            if args.graph_action == "export":
                return _run_coroutine(handle_graph_export(args, context))
            elif args.graph_action == "import":
                return _run_coroutine(handle_graph_import(args, context))
            elif args.graph_action == "prune":
                return _run_coroutine(handle_graph_prune(args, context))
            elif args.graph_action == "search":
                return _run_coroutine(handle_graph_search(args, context))
            elif args.graph_action == "belief":
                return _run_coroutine(handle_graph_belief(args, context))
            elif args.graph_action == "attack-path":
                return _run_coroutine(handle_graph_attack_path(args, context))
            elif args.graph_action == "blast-radius":
                return _run_coroutine(handle_graph_blast_radius(args, context))
            elif args.graph_action == "crown-jewels":
                return _run_coroutine(handle_graph_crown_jewels(args, context))
            return _run_coroutine(handle_graph_list_nodes(args, context))

        elif args.subcommand == "telemetry":
            if args.telemetry_action == "diff":
                return _run_coroutine(handle_telemetry_diff(args, context))
            elif args.telemetry_action == "health":
                return _run_coroutine(handle_telemetry_health(args, context))
            return _run_coroutine(handle_telemetry_snapshot(args, context))

        elif args.subcommand == "logs":
            return handle_logs(args, context)

        elif args.subcommand == "mcp":
            return _run_coroutine(handle_mcp(args, context))

        elif args.subcommand == "pipeline":
            return _run_coroutine(handle_pipeline_run(args, context))

        elif args.subcommand == "drift":
            if args.drift_action == "export-baseline":
                return _run_coroutine(handle_drift_export_baseline(args, context))
            elif args.drift_action == "audit":
                return _run_coroutine(handle_drift_audit(args, context))
            else:
                parser.print_help()
                return EXIT_USAGE_ERROR

        elif args.subcommand == "config":
            if getattr(args, "config_action", None) == "path":
                return handle_config_path(args, context)
            return handle_config_show(args, context)

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
