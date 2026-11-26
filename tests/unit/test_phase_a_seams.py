"""Regression tests for Phase A controlled-production seam repairs."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ether.common.session_sealer import SessionSealer
from ether.core.container import ContainerizedToolRunner
from ether.gateway.flags import FlagFirewall, FlagFirewallError
from ether.gateway.gate import GatePolicy
from ether.graph.store import GraphStore
from ether.mcp.security import (
    _CURRENT_AUTH_CONTEXT,
    AuthContext,
    AuthError,
    OperationType,
    SecurityMiddleware,
)
from ether.mcp.server import create_mcp_server
from ether.registry.registry import ToolRegistry
from ether.schemas.network import NetworkHost


@pytest.mark.fast
def test_flag_firewall_empty_allowed_and_positionals():
    """allowed=[] denies all optional flags, and unvalidated positionals are rejected under SAFE."""
    reg = ToolRegistry()
    reg.load_tools()
    fw = FlagFirewall(registry=reg)

    # tcp_probe has allowed = [] in manifest.toml -> any optional flag must be rejected
    with pytest.raises(FlagFirewallError, match="not in manifest"):
        fw.validate_arguments("tcp_probe", ["-sV"], GatePolicy.SAFE)

    # Unvalidated positional token rejected under SAFE
    with pytest.raises(FlagFirewallError, match="positional"):
        fw.validate_arguments("nmap", ["not-a-target-or-file"], GatePolicy.SAFE)

    # Valid target positional and flag+value pairs pass under SAFE
    assert fw.validate_arguments("nmap", ["-p", "80,443", "10.0.0.1"], GatePolicy.SAFE) == [
        "-p",
        "80,443",
        "10.0.0.1",
    ]


@pytest.mark.asyncio
@pytest.mark.fast
async def test_mcp_static_admin_ceiling_and_handler_rbac():
    """Static-admin ceiling and per-handler OperationType enforcement on MCP tools."""
    mw_disabled = SecurityMiddleware(
        signing_secret="secret",
        static_admin_token="admin-tok",
        allow_static_admin=False,
    )
    with pytest.raises(AuthError):
        await mw_disabled.authenticate_request(
            headers={"Authorization": "Bearer admin-tok"},
            client_cert=None,
            operation=OperationType.GRAPH_QUERY,
        )

    mw_capped = SecurityMiddleware(
        signing_secret="secret",
        static_admin_token="admin-tok",
        allow_static_admin=True,
        static_admin_scopes=[OperationType.GRAPH_QUERY],
    )
    ctx = await mw_capped.authenticate_request(
        headers={"Authorization": "Bearer admin-tok"},
        client_cert=None,
        operation=OperationType.GRAPH_QUERY,
    )
    assert ctx.has_scope(OperationType.GRAPH_QUERY)
    assert not ctx.has_scope(OperationType.SESSION_MUTATE)

    # Verify search_tools and manage_session enforce scopes when AuthContext is active
    store = GraphStore(":memory:")
    await store.initialize()
    try:
        server = create_mcp_server(store)
        tools = {t.name: t for t in await server.list_tools()}
        assert "search_tools" in tools
        assert "manage_session" in tools

        readonly_ctx = AuthContext(
            subject="reader",
            scopes=frozenset({OperationType.GRAPH_QUERY.value}),
            transport="http",
        )
        token = _CURRENT_AUTH_CONTEXT.set(readonly_ctx)
        try:
            # search_tools succeeds with GRAPH_QUERY
            res = await server.call_tool("search_tools", {"query": "nmap"})
            assert res is not None

            # manage_session(action="create") requires SESSION_MUTATE
            with pytest.raises(Exception, match="Error executing tool manage_session"):
                await server.call_tool("manage_session", {"action": "create", "name": "test"})
        finally:
            _CURRENT_AUTH_CONTEXT.reset(token)

        telemetry_only = AuthContext(
            subject="telemetry",
            scopes=frozenset({OperationType.TELEMETRY_READ.value}),
            transport="http",
        )
        token2 = _CURRENT_AUTH_CONTEXT.set(telemetry_only)
        try:
            with pytest.raises(Exception, match="Error executing tool search_tools"):
                await server.call_tool("search_tools", {"query": "nmap"})
        finally:
            _CURRENT_AUTH_CONTEXT.reset(token2)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_write_queue_duplicate_pik_ownership():
    """Coalesced upserts with duplicate PIKs preserve exact per-caller node ownership."""
    store = GraphStore(":memory:")
    await store.initialize()
    try:
        _, sess_id = await store.get_or_create_default_session()
        h1 = NetworkHost.create(ip="10.10.10.1")
        h2 = NetworkHost.create(ip="10.10.10.1")

        import asyncio

        r1, r2 = await asyncio.gather(
            store.write_worker.enqueue_upsert(
                sess_id, [h1], upsert_fn=store._raw_upsert_findings_batch
            ),
            store.write_worker.enqueue_upsert(
                sess_id, [h2], upsert_fn=store._raw_upsert_findings_batch
            ),
        )
        assert len(r1.node_ids) == 1
        assert len(r2.node_ids) == 1
        assert r1.node_ids == r2.node_ids
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_reopen_session_invalidates_seal_receipt(tmp_path):
    """Reopening a sealed session removes seal_receipt.json so verify_seal fails."""
    from ether.config import EtherSettings, PathsSettings

    settings = EtherSettings(paths=PathsSettings(data_dir=str(tmp_path)))
    db_path = str(tmp_path / "ether.db")
    store = GraphStore(db_path, settings=settings)
    await store.initialize()
    try:
        _, sess_id = await store.get_or_create_default_session()
        await store.close_session(sess_id)

        ok, _ = SessionSealer.verify_seal(sess_id, data_dir=str(tmp_path))
        assert ok is True

        ok_strict, msg = SessionSealer.verify_seal(
            sess_id, data_dir=str(tmp_path), require_trusted_key=True
        )
        assert ok_strict is False
        assert "Trusted public key" in msg

        await store.reopen_session(sess_id)
        ok_after, _ = SessionSealer.verify_seal(sess_id, data_dir=str(tmp_path))
        assert ok_after is False
    finally:
        await store.close()


@pytest.mark.fast
def test_container_runner_hardened_flags():
    """ContainerizedToolRunner defaults to --network=none and enforces resource/privilege limits."""
    with patch("shutil.which", return_value="/usr/bin/podman"):
        cmd_default = ContainerizedToolRunner.build_container_command(
            command=["nmap", "-sV", "10.0.0.1"],
            cwd="/tmp/work",
        )
        assert "--network=none" in cmd_default
        assert "--network=host" not in cmd_default
        assert "--security-opt=no-new-privileges" in cmd_default
        assert "--pids-limit=256" in cmd_default

        cmd_net = ContainerizedToolRunner.build_container_command(
            command=["nmap", "-sV", "10.0.0.1"],
            cwd="/tmp/work",
            allow_network=True,
        )
        assert "--network=bridge" in cmd_net
        assert "--network=host" not in cmd_net
