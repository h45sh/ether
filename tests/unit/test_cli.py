"""Unit tests for Ether headless CLI router and subcommands."""

import json

import pytest

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS
from ether.cli.router import main
from ether.graph.store import GraphStore
from ether.schemas.network import NetworkHost


def test_cli_help(capsys):
    """Verify that --help exits with 0 and prints usage."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Ether: Headless reactive process supervisor" in captured.out
    assert "doctor" in captured.out
    assert "tool" in captured.out
    assert "run" in captured.out


def test_cli_version(capsys):
    """Verify that --version exits with 0 and prints version."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Ether v" in captured.out


def test_cli_doctor(tmp_path, capsys):
    """Verify 'ether doctor' runs and outputs terminal report."""
    db_file = str(tmp_path / "doctor_cli.db")
    exit_code = main(["doctor", "--db", db_file])
    assert exit_code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "Ether System & Environmental Diagnostic Report" in captured.out
    assert "Python Runtime:" in captured.out


def test_cli_doctor_json(tmp_path, capsys):
    """Verify 'ether doctor --json' produces machine-readable JSON."""
    db_file = str(tmp_path / "doctor_cli_json.db")
    exit_code = main(["doctor", "--db", db_file, "--json"])
    assert exit_code == EXIT_SUCCESS
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["healthy"] is True
    assert "system_info" in data
    assert "checks" in data


def test_cli_tool_list_and_info(capsys):
    """Verify 'ether tool list' and 'ether tool info'."""
    # Table list
    code = main(["tool", "list"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "TOOL" in captured.out
    assert "nmap" in captured.out

    # JSON list
    code = main(["tool", "list", "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    tools = json.loads(captured.out)
    assert isinstance(tools, list)
    assert any(t["name"] == "nmap" and t.get("tier") == "subprocess" for t in tools)

    # Info
    code = main(["tool", "info", "nmap", "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    info = json.loads(captured.out)
    assert info["name"] == "nmap"
    assert info["binary"] == "nmap"
    assert info["tier"] == "subprocess"


@pytest.mark.asyncio
async def test_cli_session_and_graph_commands(tmp_path, capsys):
    """Verify session create, list, graph list-nodes, and export commands."""
    db_file = str(tmp_path / "session_cli.db")

    # 1. Create Session
    code = main(["session", "create", "CliInvestigation", "--db", db_file, "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    sess_data = json.loads(captured.out)
    sess_id = sess_data["session_id"]
    assert sess_id is not None

    # 2. List Sessions
    code = main(["session", "list", "--db", db_file, "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    sessions = json.loads(captured.out)
    assert any(s["id"] == sess_id for s in sessions)

    # 3. Insert a finding node directly to verify graph query & export
    store = GraphStore(db_file)
    await store.initialize()
    host = NetworkHost.create(ip="10.10.10.10", hostname="cli-target.lab")
    await store.upsert_finding(sess_id, host)
    await store.close()

    # 4. List Nodes
    code = main(["graph", "list-nodes", sess_id, "--db", db_file, "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    nodes = json.loads(captured.out)
    assert len(nodes) >= 1
    assert any(n["pik"].get("ip") == "10.10.10.10" for n in nodes)

    # 5. Export Graph
    export_json = str(tmp_path / "export.json")
    code = main(["graph", "export", sess_id, "-o", export_json, "--db", db_file])
    assert code == EXIT_SUCCESS
    capsys.readouterr()  # clear buffer
    with open(export_json, "r") as f:
        exported = json.load(f)
    assert exported["session_id"] == sess_id
    assert len(exported["nodes"]) >= 1

    # 6. Telemetry Snapshot
    code = main(["telemetry", "snapshot", sess_id, "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    snap = json.loads(captured.out)
    assert snap["session_id"] == sess_id
    assert snap["graph_summary"]["total_nodes"] >= 1

    # 7. Session Verify Audit
    code = main(["session", "verify-audit", sess_id, "--db", db_file, "--json"])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    audit_data = json.loads(captured.out)
    assert audit_data["session_id"] == sess_id
    assert audit_data["valid"] is True


def test_cli_run_blocks_cloud_metadata(tmp_path, capsys):
    """Verify 'ether run' preflight gate blocks cloud metadata under safe policy."""
    db_file = str(tmp_path / "metadata_block.db")
    # 169.254.169.254 is AWS/cloud link-local metadata IP
    code = main(["run", "nmap", "169.254.169.254", "--db", db_file])
    assert code == EXIT_RUNTIME_ERROR
    captured = capsys.readouterr()
    assert (
        "Preflight validation failed" in captured.err
        or "SSRF_CLOUD_METADATA_PROHIBITED" in captured.err
    )


@pytest.mark.asyncio
async def test_cli_graph_encrypted_export_and_import(tmp_path, capsys):
    """Verify 'ether graph export --encrypt' and 'ether graph import' roundtrip."""
    db_source = str(tmp_path / "source.db")
    db_target = str(tmp_path / "target.db")
    enc_archive = str(tmp_path / "session_export.enc")
    passphrase = "Ultra-Secure-Argon2-Passphrase!"

    # 1. Populate source DB
    store = GraphStore(db_source)
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()
    h = NetworkHost.create(ip="172.16.0.5", hostname="encrypted-host.corp")
    await store.upsert_finding(sess_id, h)
    await store.close()

    # 2. Encrypted Export
    code = main(
        [
            "graph",
            "export",
            sess_id,
            "-o",
            enc_archive,
            "--encrypt",
            "--passphrase",
            passphrase,
            "--db",
            db_source,
        ]
    )
    assert code == EXIT_SUCCESS
    capsys.readouterr()

    # Verify encrypted archive starts with magic header
    with open(enc_archive, "rb") as f:
        data = f.read()
    assert data.startswith(b"ETHER_SECURE_ARC")

    # 3. Import into new target DB
    code = main(
        [
            "graph",
            "import",
            enc_archive,
            "--passphrase",
            passphrase,
            "--db",
            db_target,
            "--json",
        ]
    )
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    import_result = json.loads(captured.out)
    assert import_result["imported_nodes"] >= 1

    # 4. Verify target DB has the decrypted node
    target_store = GraphStore(db_target)
    await target_store.initialize()
    nodes = await target_store.get_all_nodes(import_result["session_id"])
    assert len(nodes) >= 1
    piks = [json.loads(n["pik_json"]).get("ip") for n in nodes if "pik_json" in n]
    assert "172.16.0.5" in piks
    await target_store.close()


def test_cli_mcp_parser_and_help(capsys):
    """Verify 'ether mcp --help' surfaces MCP CLI options."""
    with pytest.raises(SystemExit) as exc:
        main(["mcp", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "--transport" in captured.out
    assert "--session-id" in captured.out
    assert "--port" in captured.out


@pytest.mark.asyncio
async def test_cli_graph_list_nodes_include_stale_and_prune(tmp_path, capsys):
    """Verify 'ether graph list-nodes --include-stale' and 'ether graph prune'."""
    db_file = str(tmp_path / "graph_stale_cli.db")
    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    h1 = NetworkHost.create(ip="10.0.0.1")
    h2 = NetworkHost.create(ip="10.0.0.2")
    h1_id = await store.upsert_finding(sess_id, h1)
    await store.upsert_finding(sess_id, h2)

    # Decay h1 to stale with an old last_seen_at
    async with store.connection() as db:
        await db.execute(
            "UPDATE nodes SET status = 'stale', last_seen_at = '2020-01-01 00:00:00' WHERE id = ?",
            (h1_id,),
        )
        await db.commit()
    await store.close()

    # 1. Default list-nodes without --include-stale (JSON)
    code = main(["graph", "list-nodes", sess_id, "--json", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    nodes = json.loads(captured.out)
    assert len(nodes) == 1
    assert nodes[0]["pik"]["ip"] == "10.0.0.2"

    # 2. list-nodes with --include-stale (JSON)
    code = main(["graph", "list-nodes", sess_id, "--include-stale", "--json", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    nodes_all = json.loads(captured.out)
    assert len(nodes_all) == 2

    # 3. Prune stale nodes
    code = main(["graph", "prune", sess_id, "--max-age", "3600", "--json", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    prune_res = json.loads(captured.out)
    assert prune_res["pruned_nodes"] == 1

    # 4. list-nodes with --include-stale now only has 1 node left
    code = main(["graph", "list-nodes", sess_id, "--include-stale", "--json", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    nodes_remaining = json.loads(captured.out)
    assert len(nodes_remaining) == 1
    assert nodes_remaining[0]["pik"]["ip"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_cli_graph_search(tmp_path, capsys):
    """Verify 'ether graph search' tabular and JSON output."""
    db_file = str(tmp_path / "search_cli.db")
    store = GraphStore(db_file)
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    h = NetworkHost.create(ip="10.10.10.5", hostname="db-primary.internal", os="Debian Linux")
    await store.upsert_finding(sess_id, h)
    await store.close()

    # 1. Search Table output
    code = main(["graph", "search", sess_id, "Debian Linux database host", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "SCORE" in captured.out
    assert "NODE ID" in captured.out
    assert "10.10.10.5" in captured.out

    # 2. Search JSON output
    code = main(
        ["graph", "search", sess_id, "Debian Linux database host", "--json", "--db", db_file]
    )
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    results = json.loads(captured.out)
    assert len(results) >= 1
    assert results[0]["schema_type"] == "network.host"
    assert "similarity" in results[0]
    assert results[0]["similarity"] > 0.0

    # 3. Search with no matches / min_score 0.99
    code = main(["graph", "search", sess_id, "unrelated query", "-m", "0.99", "--db", db_file])
    assert code == EXIT_SUCCESS
    captured = capsys.readouterr()
    assert "No semantic matches found" in captured.out
