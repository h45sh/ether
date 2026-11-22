"""Unit tests for ExecutionContext and ToolAdapter dual-execution protocol."""

from typing import Any, AsyncIterator, Dict, List

import pytest

from ether.common.context import ExecutionContext
from ether.core.session import ExecutionSession
from ether.gateway.gate import ActionGateway, GatePolicy
from ether.graph.store import GraphStore
from ether.registry.adapter import ToolAdapter
from ether.registry.registry import ToolRegistry
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost
from ether.schemas.power import ActionRequest
from tests.unit.test_execution_session import FakeInMemoryRunner


class DummyTierBCoroutineMockAdapter(ToolAdapter):
    """Subprocess adapter that uses default execute_action."""

    name = "dummy_tier_b"
    execution_tier = "subprocess"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        return ["echo", "test"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        yield NetworkHost.create(ip="192.168.1.100")


class DummyTierACoroutineAdapter(ToolAdapter):
    """Native coroutine adapter overriding execute_action directly."""

    name = "dummy_tier_a"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        return []

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        if False:
            yield

    async def execute_action(
        self, target: BaseFinding, params: Dict[str, Any], context: ExecutionContext
    ) -> AsyncIterator[BaseFinding]:
        await context.spool_line("[native-probe] starting in-process execution\n")
        yield NetworkHost.create(ip="10.20.30.40", hostname="native.lab")
        await context.spool_line("[native-probe] probe finished\n")


@pytest.mark.asyncio
async def test_execution_context_spooling():
    """Verify ExecutionContext.spool_line forwards lines and error status to callback."""
    spooled: List[tuple[str, bool]] = []

    async def _mock_spool(line: str, is_error: bool) -> None:
        spooled.append((line, is_error))

    ctx = ExecutionContext(
        action_id="act-123",
        session_id="sess-456",
        spool_fn=_mock_spool,
    )
    await ctx.spool_line("stdout message", is_error=False)
    await ctx.spool_line("stderr warning", is_error=True)

    assert spooled == [("stdout message", False), ("stderr warning", True)]


@pytest.mark.asyncio
async def test_tier_b_subprocess_adapter_default_execute_action():
    """Verify default ToolAdapter.execute_action delegates to context.runner."""
    runner = FakeInMemoryRunner(output_chunks=["192.168.1.100\n"])
    spooled: List[str] = []

    async def _mock_spool(line: str, is_error: bool) -> None:
        spooled.append(line)

    ctx = ExecutionContext(
        action_id="act-b-1",
        session_id="sess-1",
        runner=runner,
        spool_fn=_mock_spool,
    )
    adapter = DummyTierBCoroutineMockAdapter()
    target = NetworkHost.create(ip="192.168.1.1")

    findings = []
    async for f in adapter.execute_action(target, {}, ctx):
        findings.append(f)

    assert len(findings) == 1
    assert findings[0].pik["ip"] == "10.0.0.1"
    assert any("192.168.1.100" in s for s in spooled)


@pytest.mark.asyncio
async def test_tier_a_native_coroutine_execute_action():
    """Verify Tier A native coroutine adapter runs without runner and spools wire traces."""
    spooled: List[str] = []

    async def _mock_spool(line: str, is_error: bool) -> None:
        spooled.append(line)

    ctx = ExecutionContext(
        action_id="act-a-1",
        session_id="sess-1",
        runner=None,  # Tier A does not need a subprocess runner
        spool_fn=_mock_spool,
    )
    adapter = DummyTierACoroutineAdapter()
    target = NetworkHost.create(ip="10.20.30.1")

    findings = []
    async for f in adapter.execute_action(target, {}, ctx):
        findings.append(f)

    assert len(findings) == 1
    assert findings[0].pik["ip"] == "10.20.30.40"
    assert spooled == [
        "[native-probe] starting in-process execution\n",
        "[native-probe] probe finished\n",
    ]


@pytest.mark.asyncio
async def test_execution_session_executes_native_coroutine():
    """Verify ExecutionSession transparently executes and records findings for a native coroutine."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws_id, sess_id = await store.get_or_create_default_session()

    target_host = NetworkHost.create(ip="10.0.0.1", hostname="target.lab")
    target_node_id = await store.upsert_finding(sess_id, target_host)

    registry = ToolRegistry()
    coro_adapter = DummyTierACoroutineAdapter()
    registry.tools["dummy_tier_a"] = {
        "manifest": None,
        "adapter": coro_adapter,
        "adapter_class": DummyTierACoroutineAdapter,
        "available": True,
    }

    gateway = ActionGateway(registry=registry, store=store, policy=GatePolicy.SAFE)
    exec_sess = ExecutionSession(
        store=store, registry=registry, gateway=gateway, command_runner=FakeInMemoryRunner()
    )

    from uuid import UUID

    action = ActionRequest(
        session_id=UUID(sess_id),
        tool_name="dummy_tier_a",
        target_entity_id=target_node_id,
    )

    job_id = await exec_sess.dispatch(action)
    task = exec_sess.get_running_task(job_id)
    if task:
        await task

    # Verify findings made it into the graph store
    import json

    nodes = await store.get_all_nodes(sess_id)
    ips = [json.loads(n["pik_json"]).get("ip") for n in nodes if "pik_json" in n]
    assert "10.20.30.40" in ips

    # Verify output was captured in memory history
    output = "".join(exec_sess.get_output_history(action.action_id))
    assert "[native-probe] starting in-process execution" in output
    assert "[native-probe] probe finished" in output

    await store.close()
