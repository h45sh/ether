"""Unit tests for Reactive Pipeline DAG Engine (Ticket 09)."""

import pytest

from ether.core.pipeline import PipelineEngine, PipelineParser
from ether.graph.store import GraphStore
from ether.registry.adapter import ToolAdapter
from ether.registry.registry import ToolRegistry
from ether.schemas.network import NetworkHost, NetworkService


class MockReconAdapter(ToolAdapter):
    """Mock recon tool producing NetworkHost findings."""

    name = "mock_recon"
    execution_tier = "coroutine"

    def build_command(self, target, params=None):
        return ["mock", "recon"]

    def validate_install(self):
        return True

    async def execute_action(self, target, params, context):
        for i in range(3):
            yield NetworkHost.create(ip=f"10.0.0.{i + 1}")

    async def parse_output(self, output, target, context=None):
        pass


class MockPortAdapter(ToolAdapter):
    """Mock port tool consuming NetworkHost and producing NetworkService findings."""

    name = "mock_port"
    execution_tier = "coroutine"

    def build_command(self, target, params=None):
        return ["mock", "port"]

    def validate_install(self):
        return True

    async def execute_action(self, target, params, context):
        ip = getattr(target, "ip", None) or target.pik.get("ip", "127.0.0.1")
        yield NetworkService.create(host_ip=ip, port=80, protocol="tcp", service_name="http")

    async def parse_output(self, output, target, context=None):
        pass


@pytest.fixture
def mock_registry():
    registry = ToolRegistry(tools_dir=None)
    registry.tools["mock_recon"] = {
        "adapter": MockReconAdapter(),
        "manifest": None,
    }
    registry.tools["mock_port"] = {
        "adapter": MockPortAdapter(),
        "manifest": None,
    }
    return registry


def test_pipeline_parser_valid_syntax(mock_registry):
    stages = PipelineParser.parse("mock_recon(target=example.com) | mock_port", mock_registry)
    assert len(stages) == 2
    assert stages[0].tool_name == "mock_recon"
    assert stages[0].params["target"] == "example.com"
    assert stages[1].tool_name == "mock_port"
    assert stages[1].params == {}


def test_pipeline_parser_invalid_tool(mock_registry):
    with pytest.raises(ValueError, match="Unknown tool 'nonexistent_tool'"):
        PipelineParser.parse("mock_recon | nonexistent_tool", mock_registry)


def test_pipeline_parser_empty():
    registry = ToolRegistry()
    assert PipelineParser.parse("", registry) == []


@pytest.mark.asyncio
async def test_pipeline_engine_streaming(mock_registry):
    engine = PipelineEngine(registry=mock_registry, max_concurrent=5, queue_size=10)
    findings = []
    async for finding in engine.execute_pipeline("mock_recon | mock_port"):
        findings.append(finding)

    # mock_recon produces 3 hosts, mock_port produces 1 service for each host -> 3 services
    assert len(findings) == 3
    for f in findings:
        assert isinstance(f, NetworkService)
        assert f.pik["port"] == 80


@pytest.mark.asyncio
async def test_pipeline_engine_with_graph_persistence(mock_registry, tmp_path):
    db_file = str(tmp_path / "pipe_test.db")
    store = GraphStore(db_file)
    await store.initialize()

    ws_id = await store.create_workspace("PipeWS")
    sess_id = await store.create_session(ws_id, "PipeSess")

    engine = PipelineEngine(registry=mock_registry, store=store, max_concurrent=5)
    findings = []
    async for finding in engine.execute_pipeline("mock_recon | mock_port", session_id=sess_id):
        findings.append(finding)

    assert len(findings) == 3

    # Verify findings from all stages were stored in GraphStore (3 hosts + 3 services = 6 nodes)
    nodes = await store.get_all_nodes(sess_id)
    assert len(nodes) == 6
    types = {n["schema_type"] for n in nodes}
    assert "network.host" in types
    assert "network.service" in types

    await store.close()


@pytest.mark.asyncio
async def test_cli_pipeline_run(tmp_path, monkeypatch, capsys):
    from argparse import Namespace

    from ether.cli.commands.pipeline import handle_pipeline_run
    from ether.cli.context import CliContext
    from ether.gateway.gate import GatePolicy

    db_file = str(tmp_path / "test.db")
    ctx = CliContext(
        data_dir=str(tmp_path),
        db_path=db_file,
        tools_dir=None,
        is_json=True,
        verbose=False,
        policy=GatePolicy.UNRESTRICTED,
    )

    # Monkeypatch ToolRegistry to include mock tools
    def mock_load(self):
        self.tools["mock_recon"] = {"adapter": MockReconAdapter(), "manifest": None}
        self.tools["mock_port"] = {"adapter": MockPortAdapter(), "manifest": None}

    monkeypatch.setattr(ToolRegistry, "load_tools", mock_load)

    async with ctx.open_store() as store:
        ws_id = await store.create_workspace("TestWS")
        sess_id = await store.create_session(ws_id, "cli-session")

    args = Namespace(expression="mock_recon | mock_port", session=sess_id)
    code = await handle_pipeline_run(args, ctx)
    assert code == 0
    captured = capsys.readouterr()
    assert '"count": 3' in captured.out
    assert '"expression": "mock_recon | mock_port"' in captured.out


def test_pipeline_engine_defaults_command_runner_to_executor(mock_registry):
    from ether.core.executor import Executor

    engine = PipelineEngine(registry=mock_registry)
    assert isinstance(engine.command_runner, Executor)


@pytest.mark.asyncio
async def test_pipeline_engine_executes_tier_b_via_command_runner_and_infers_domain(tmp_path):
    from ether.core.session import CommandRunner

    seen_targets = []
    runner_calls = []

    class FakePipelineRunner(CommandRunner):
        async def run(
            self,
            adapter,
            target,
            params,
            task_id,
            cwd,
            env=None,
            use_shell=False,
            shell_path=None,
            on_output=None,
            on_error_output=None,
            timeout_seconds=None,
        ):
            runner_calls.append((adapter.name, target.schema_type, params))
            yield NetworkHost.create(ip="93.184.216.34")

        async def stop(self, task_id: str) -> None:
            pass

    class TierBAdapter(ToolAdapter):
        name = "tier_b_tool"
        execution_tier = "subprocess"

        def validate_install(self):
            return True

        def build_command(self, target, params):
            return ["tier_b", str(target.pik)]

        async def parse_output(self, raw_stdout, target, context=None):
            raise AssertionError("PipelineEngine must not call parse_output directly for Tier B")
            yield  # pragma: no cover

        async def execute_action(self, target, params, context):
            seen_targets.append(target)
            async for f in super().execute_action(target, params, context):
                yield f

    reg = ToolRegistry(tools_dir=None)
    reg.tools["tier_b_tool"] = {"adapter": TierBAdapter(), "manifest": None}

    store = GraphStore(str(tmp_path / "pipe_tier_b.db"))
    await store.initialize()
    ws_id = await store.create_workspace("WS")
    sess_id = await store.create_session(ws_id, "Sess")

    runner = FakePipelineRunner()
    engine = PipelineEngine(registry=reg, store=store, command_runner=runner)

    findings = []
    async for f in engine.execute_pipeline("tier_b_tool(target=example.com)", session_id=sess_id):
        findings.append(f)

    assert len(findings) == 1
    assert len(runner_calls) == 1
    assert seen_targets[0].schema_type == "domain.info"
    assert seen_targets[0].pik["domain"] == "example.com"

    nodes = await store.get_all_nodes(sess_id)
    assert len(nodes) == 1
    assert nodes[0]["schema_type"] == "network.host"
    await store.close()
