"""Integration tests for high-fidelity MCP error diagnostics and taxonomy.

Verifies that execution failures return structured telemetry payloads containing:
exit_code, stderr_snippet, error_category, and is_error=True utilizing the
ExecutionErrorCategory taxonomy enum without crashing the JSON-RPC session.
"""

import json

import pytest

from ether.common.exceptions import ExecutionErrorCategory
from ether.core.session import ExecutionSession
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.graph.store import GraphStore
from ether.mcp.server import create_mcp_server
from ether.registry.registry import ToolRegistry
from tests.unit.test_execution_session import FakeInMemoryRunner


@pytest.mark.asyncio
async def test_mcp_scope_blocked_diagnostic():
    """Verify preflight SSRF/cloud metadata rejection returns SCOPE_BLOCKED structured payload."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    registry = ToolRegistry()
    registry.load_tools()
    runner = FakeInMemoryRunner()
    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=runner
    )

    server = create_mcp_server(
        store=store,
        default_session_id=sess_id,
        gateway=gateway,
        registry=registry,
        execution_session=exec_sess,
    )

    # Cloud metadata IP blocked under SAFE policy
    res = await server.call_tool(
        "execute_tool",
        {"tool_name": "whois", "target": "169.254.169.254"},
    )
    assert res.is_error is False  # Protocol remains intact (no JSON-RPC crash)
    payload = json.loads(res.content[0].text)

    assert payload["is_error"] is True
    assert payload["error_category"] == ExecutionErrorCategory.SCOPE_BLOCKED.value
    assert payload["exit_code"] == 1
    assert "rejected by policy safe" in payload["message"]
    assert "stderr_snippet" in payload

    # Verify session is still alive and responsive to subsequent queries
    res_query = await server.call_tool("query_graph", {})
    assert res_query.is_error is False

    await exec_sess.shutdown()
    await store.close()


@pytest.mark.asyncio
async def test_mcp_binary_missing_diagnostic():
    """Verify unregistered or missing tool returns BINARY_MISSING structured payload."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    registry = ToolRegistry()
    runner = FakeInMemoryRunner()
    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=runner
    )

    server = create_mcp_server(
        store=store,
        default_session_id=sess_id,
        gateway=gateway,
        registry=registry,
        execution_session=exec_sess,
    )

    res = await server.call_tool(
        "execute_tool",
        {"tool_name": "non_existent_tool_xyz", "target": "10.0.0.1"},
    )
    assert res.is_error is False
    payload = json.loads(res.content[0].text)

    assert payload["is_error"] is True
    assert payload["error_category"] == ExecutionErrorCategory.BINARY_MISSING.value
    assert payload["exit_code"] == 127
    assert "Tool 'non_existent_tool_xyz' is not registered" in payload["stderr_snippet"]

    await exec_sess.shutdown()
    await store.close()


@pytest.mark.asyncio
async def test_mcp_target_unreachable_diagnostic():
    """Verify execution failure due to network/host unreachable returns TARGET_UNREACHABLE."""
    class ConnectionRefusedRunner(FakeInMemoryRunner):
        async def run(self, *args, **kwargs):
            raise ConnectionRefusedError("Connection refused by remote host 10.254.254.1:80")
            if False:
                yield

    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    registry = ToolRegistry()
    registry.load_tools()
    whois_tool = registry.get_tool("whois")
    if whois_tool and whois_tool.get("adapter"):
        whois_tool["adapter"].validate_install = lambda: True

    runner = ConnectionRefusedRunner()
    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=runner
    )

    server = create_mcp_server(
        store=store,
        default_session_id=sess_id,
        gateway=gateway,
        registry=registry,
        execution_session=exec_sess,
    )

    res = await server.call_tool(
        "execute_tool",
        {"tool_name": "whois", "target": "10.254.254.1"},
    )
    assert res.is_error is False
    payload = json.loads(res.content[0].text)

    assert payload["is_error"] is True
    assert payload["error_category"] == ExecutionErrorCategory.TARGET_UNREACHABLE.value
    assert "Connection refused" in payload["stderr_snippet"]

    await exec_sess.shutdown()
    await store.close()


@pytest.mark.asyncio
async def test_mcp_command_timeout_diagnostic():
    """Verify execution failure due to command timeout returns COMMAND_TIMEOUT."""
    class TimeoutRunner(FakeInMemoryRunner):
        async def run(self, *args, **kwargs):
            raise TimeoutError("Command timed out after 30 seconds")
            if False:
                yield

    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    registry = ToolRegistry()
    registry.load_tools()
    whois_tool = registry.get_tool("whois")
    if whois_tool and whois_tool.get("adapter"):
        whois_tool["adapter"].validate_install = lambda: True

    runner = TimeoutRunner()
    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=runner
    )

    server = create_mcp_server(
        store=store,
        default_session_id=sess_id,
        gateway=gateway,
        registry=registry,
        execution_session=exec_sess,
    )

    res = await server.call_tool(
        "execute_tool",
        {"tool_name": "whois", "target": "10.0.0.1"},
    )
    assert res.is_error is False
    payload = json.loads(res.content[0].text)

    assert payload["is_error"] is True
    assert payload["error_category"] == ExecutionErrorCategory.COMMAND_TIMEOUT.value
    assert "timed out" in payload["stderr_snippet"].lower()

    await exec_sess.shutdown()
    await store.close()


@pytest.mark.asyncio
async def test_mcp_non_zero_exit_diagnostic():
    """Verify execution failure with general error returns NON_ZERO_EXIT."""
    class GenericErrorRunner(FakeInMemoryRunner):
        async def run(self, *args, **kwargs):
            raise RuntimeError("Fatal internal error in parser syntax")
            if False:
                yield

    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    registry = ToolRegistry()
    registry.load_tools()
    whois_tool = registry.get_tool("whois")
    if whois_tool and whois_tool.get("adapter"):
        whois_tool["adapter"].validate_install = lambda: True

    runner = GenericErrorRunner()
    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=runner
    )

    server = create_mcp_server(
        store=store,
        default_session_id=sess_id,
        gateway=gateway,
        registry=registry,
        execution_session=exec_sess,
    )

    res = await server.call_tool(
        "execute_tool",
        {"tool_name": "whois", "target": "10.0.0.1"},
    )
    assert res.is_error is False
    payload = json.loads(res.content[0].text)

    assert payload["is_error"] is True
    assert payload["error_category"] == ExecutionErrorCategory.NON_ZERO_EXIT.value
    assert "Fatal internal error" in payload["stderr_snippet"]

    await exec_sess.shutdown()
    await store.close()
