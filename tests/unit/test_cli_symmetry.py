"""Unit tests verifying CLI and MCP parameter symmetry and harmonization."""

import pytest

from ether.cli.commands.telemetry import handle_telemetry_snapshot
from ether.cli.context import CliContext
from ether.cli.router import build_parser
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


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
