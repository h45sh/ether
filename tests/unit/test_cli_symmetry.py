"""Unit tests verifying CLI and MCP parameter symmetry and harmonization."""

import pytest

from ether.cli.commands.telemetry import handle_telemetry_snapshot
from ether.cli.context import CliContext
from ether.cli.router import build_parser, normalize_cli_args
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


@pytest.mark.fast
def test_cli_positional_keyword_symmetry():
    parser = build_parser()

    # 1. run command: positional vs keyword
    argv1 = normalize_cli_args(["run", "nmap", "127.0.0.1"])
    args1 = parser.parse_args(argv1)
    argv2 = normalize_cli_args(["run", "--tool", "nmap", "--target", "127.0.0.1"])
    args2 = parser.parse_args(argv2)
    assert args1.tool == args2.tool == "nmap"
    assert args1.target == args2.target == "127.0.0.1"

    # 2. session list: positional vs keyword
    argv3 = normalize_cli_args(["session", "list", "ws-456"])
    args3 = parser.parse_args(argv3)
    argv4 = normalize_cli_args(["session", "list", "--workspace-id", "ws-456"])
    args4 = parser.parse_args(argv4)
    assert args3.workspace_id == args4.workspace_id == "ws-456"

    # 3. graph list-nodes: positional vs keyword
    argv5 = normalize_cli_args(["graph", "list-nodes", "sess-789"])
    args5 = parser.parse_args(argv5)
    argv6 = normalize_cli_args(["graph", "list-nodes", "--session-id", "sess-789"])
    args6 = parser.parse_args(argv6)
    assert args5.session_id == args6.session_id == "sess-789"

    # 4. graph export: positional vs keyword
    argv7 = normalize_cli_args(["graph", "export", "sess-101", "out.json"])
    args7 = parser.parse_args(argv7)
    argv8 = normalize_cli_args(["graph", "export", "--session-id", "sess-101", "--output", "out.json"])
    args8 = parser.parse_args(argv8)
    assert args7.session_id == args8.session_id == "sess-101"
    assert args7.output == args8.output == "out.json"

    # 5. tool info: positional vs keyword
    argv9 = normalize_cli_args(["tool", "info", "subfinder"])
    args9 = parser.parse_args(argv9)
    argv10 = normalize_cli_args(["tool", "info", "--name", "subfinder"])
    args10 = parser.parse_args(argv10)
    assert args9.name == args10.name == "subfinder"


@pytest.mark.fast
def test_cli_parser_budget_alias():
    parser = build_parser()
    # Test --max-tokens
    args1 = parser.parse_args(["telemetry", "snapshot", "sess-123", "--max-tokens", "2500"])
    assert args1.max_tokens == 2500
    assert args1.budget is None

    # Test --budget alias
    args2 = parser.parse_args(["telemetry", "snapshot", "sess-123", "--budget", "1800"])
    assert args2.budget == 1800


@pytest.mark.asyncio
async def test_telemetry_snapshot_budget_and_max_tokens_parity(tmp_path):
    db_file = tmp_path / "test_store.db"
    store = GraphStore(str(db_file))
    await store.initialize()
    ws_id = await store.create_workspace("TestWS")
    sess_id = await store.create_session(ws_id, "TestSess")

    # Add finding
    host = NetworkHost.create(ip="10.0.0.5")
    await store.upsert_finding(sess_id, host)

    from ether.gateway.gate import GatePolicy

    context = CliContext(
        data_dir=str(tmp_path),
        db_path=str(db_file),
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.SAFE,
    )

    class ArgsBudget:
        session_id = sess_id
        budget = 3000
        max_tokens = 4000
        entity_id = None

    class ArgsMaxTokens:
        session_id = sess_id
        budget = None
        max_tokens = 3000
        entity_id = None

    # Both should execute without error
    ret1 = await handle_telemetry_snapshot(ArgsBudget(), context)
    ret2 = await handle_telemetry_snapshot(ArgsMaxTokens(), context)
    assert ret1 == 0
    assert ret2 == 0
