"""Unit tests verifying universal CLI -j/--json symmetry, un-truncated 64-char node IDs, and stderr isolation."""

import json
from io import StringIO
from unittest.mock import patch

import pytest

from ether.cli.commands.graph import handle_graph_list_nodes
from ether.cli.commands.session import handle_session_create, handle_session_list
from ether.cli.commands.telemetry import handle_telemetry_health
from ether.cli.context import CliContext
from ether.cli.formatters import print_error
from ether.cli.router import build_parser, normalize_cli_args
from ether.gateway.gate import GatePolicy
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


@pytest.mark.fast
def test_cli_json_flag_placement_symmetry():
    """Verify -j/--json works identically regardless of placement in argv."""
    parser = build_parser()

    cases = [
        # (argv, expected_subcommand, expected_action, is_json)
        (["-j", "session", "list"], "session", "list", True),
        (["session", "-j", "list"], "session", "list", True),
        (["session", "list", "-j"], "session", "list", True),
        (["--json", "session", "list"], "session", "list", True),
        (["session", "--json", "list"], "session", "list", True),
        (["session", "list", "--json"], "session", "list", True),
        (["graph", "-j", "list-nodes", "sess-1"], "graph", "list-nodes", True),
        (["graph", "list-nodes", "-j", "sess-1"], "graph", "list-nodes", True),
        (["graph", "list-nodes", "sess-1", "-j"], "graph", "list-nodes", True),
        (["telemetry", "-j", "health"], "telemetry", "health", True),
        (["telemetry", "health", "-j"], "telemetry", "health", True),
    ]

    for argv, expected_subcmd, expected_action, expected_json in cases:
        norm_argv = normalize_cli_args(argv)
        args = parser.parse_args(norm_argv)
        assert args.subcommand == expected_subcmd, f"Failed subcmd for {argv}"
        action_attr = f"{expected_subcmd}_action"
        if hasattr(args, action_attr):
            assert getattr(args, action_attr) == expected_action, f"Failed action for {argv}"
        assert getattr(args, "json", False) is expected_json, f"Failed json flag for {argv}"


@pytest.mark.fast
def test_print_error_stderr_isolation():
    """Verify print_error routes strictly to stderr, keeping stdout clean for JSON."""
    out_buf = StringIO()
    err_buf = StringIO()

    with patch("sys.stdout", out_buf), patch("sys.stderr", err_buf):
        print_error("Preflight validation failed")

    assert out_buf.getvalue() == "", "stdout must remain clean when errors are logged"
    assert "[!] Error: Preflight validation failed" in err_buf.getvalue()


@pytest.mark.asyncio
async def test_graph_list_nodes_full_64_char_node_id_in_json(tmp_path):
    """Verify graph list-nodes returns un-truncated 64-character node IDs in JSON mode."""
    db_file = tmp_path / "test_store.db"
    store = GraphStore(str(db_file))
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    host = NetworkHost.create(ip="192.168.1.100")
    await store.upsert_finding(sess_id, host)
    expected_full_id = store.generate_node_id(host.schema_type, host.pik)
    assert len(expected_full_id) == 64

    context = CliContext(
        data_dir=str(tmp_path),
        db_path=str(db_file),
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    class ArgsListNodes:
        session_id = sess_id
        type = None
        include_stale = False
        unmask = False

    out_buf = StringIO()
    with patch("sys.stdout", out_buf):
        ret = await handle_graph_list_nodes(ArgsListNodes(), context)
        assert ret == 0

    stdout_text = out_buf.getvalue()
    parsed = json.loads(stdout_text)
    assert isinstance(parsed, list)
    assert len(parsed) >= 1

    node = next(n for n in parsed if n["schema_type"] == "network.host")
    assert node["id"] == expected_full_id
    assert len(node["id"]) == 64, "Node ID in JSON output must be full 64-character SHA-256 hash"
    await store.close()


@pytest.mark.asyncio
async def test_session_commands_json_symmetry(tmp_path):
    """Verify session create and list subcommands produce clean machine-readable JSON."""
    db_file = tmp_path / "test_store.db"
    store = GraphStore(str(db_file))
    await store.initialize()
    ws_id = await store.create_workspace("TestWS")

    context = CliContext(
        data_dir=str(tmp_path),
        db_path=str(db_file),
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    # 1. session create
    class ArgsCreate:
        name = "Symmetry Session"
        workspace_id = ws_id

    out_buf1 = StringIO()
    with patch("sys.stdout", out_buf1):
        ret = await handle_session_create(ArgsCreate(), context)
        assert ret == 0

    create_data = json.loads(out_buf1.getvalue())
    assert create_data["name"] == "Symmetry Session"
    assert "session_id" in create_data
    sess_id = create_data["session_id"]

    # 2. session list
    class ArgsList:
        workspace_id = ws_id

    out_buf2 = StringIO()
    with patch("sys.stdout", out_buf2):
        ret = await handle_session_list(ArgsList(), context)
        assert ret == 0

    list_data = json.loads(out_buf2.getvalue())
    assert any(s["id"] == sess_id for s in list_data)
    await store.close()


@pytest.mark.asyncio
async def test_telemetry_health_json_output(tmp_path):
    """Verify telemetry health produces valid JSON."""
    db_file = tmp_path / "test_store.db"
    store = GraphStore(str(db_file))
    await store.initialize()

    context = CliContext(
        data_dir=str(tmp_path),
        db_path=str(db_file),
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    class ArgsHealth:
        prometheus = False

    out_buf = StringIO()
    with patch("sys.stdout", out_buf):
        ret = await handle_telemetry_health(ArgsHealth(), context)
        assert ret == 0

    health_data = json.loads(out_buf.getvalue())
    assert "open_fds" in health_data
    assert "resident_memory_bytes" in health_data
    await store.close()
