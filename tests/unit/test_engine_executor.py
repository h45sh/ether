import pytest

from ether.core.executor import Executor, sanitize_subprocess_env
from ether.schemas.network import NetworkHost
from tests.fixtures.mock_tools import MockNmapAdapter


@pytest.mark.asyncio
async def test_executor_run_tool():
    executor = Executor()
    target = NetworkHost.create(ip="127.0.0.1")
    adapter = MockNmapAdapter()

    findings = []
    async for f in executor.run_tool(adapter, target, {}):
        findings.append(f)

    assert len(findings) == 1
    assert findings[0].schema_type == "network.service"
    assert findings[0].pik["host_ip"] == "127.0.0.1"


class MockHangingAdapter(MockNmapAdapter):
    def build_command(self, target, params):
        return ["sleep", "5"]

    async def parse_output(self, raw_stdout, target, context=None):
        if False:
            yield


@pytest.mark.asyncio
async def test_executor_timeout():
    executor = Executor()
    target = NetworkHost.create(ip="127.0.0.1")
    adapter = MockHangingAdapter()

    output_lines = []

    async def record_output(text):
        output_lines.append(text)

    with pytest.raises(TimeoutError):
        async for _ in executor.run_tool(
            adapter, target, {}, timeout_seconds=0.2, on_output=record_output
        ):
            pass

    assert any("TIMEOUT" in line for line in output_lines)


def test_sanitize_subprocess_env():
    raw_env = {
        "PATH": "/usr/bin:/bin",
        "USER": "analyst",
        "ETHER_API_KEY": "secret_key_123",
        "ETHER_API_BASE": "https://api.openai.com",
        "GROQ_API_KEY": "gsk_test123",
        "OPENAI_API_KEY": "sk-test456",
        "ANTHROPIC_API_KEY": "ant-test789",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "GITHUB_TOKEN": "ghp_token",
        "DEEPSEEK_API_KEY": "sk-deepseek",
        "PERPLEXITY_API_KEY": "pplx-secret",
        "PPLX_TOKEN": "token123",
        "HUGGINGFACE_TOKEN": "hf_abc",
        "HF_TOKEN": "hf_xyz",
        "VAULT_TOKEN": "s.vaulttoken",
        "SSH_PRIVATE_KEY": "-----BEGIN OPENSSH PRIVATE KEY-----",  # codeguard: ignore[SECRET_PRIVATE_KEY]
    }
    cleaned = sanitize_subprocess_env(raw_env)
    assert cleaned["PATH"] == "/usr/bin:/bin"
    assert cleaned["USER"] == "analyst"
    for secret in [
        "ETHER_API_KEY",
        "ETHER_API_BASE",
        "GROQ_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "DEEPSEEK_API_KEY",
        "PERPLEXITY_API_KEY",
        "PPLX_TOKEN",
        "HUGGINGFACE_TOKEN",
        "HF_TOKEN",
        "VAULT_TOKEN",
        "SSH_PRIVATE_KEY",
    ]:
        assert secret not in cleaned


class _ExitCodeAdapter(MockNmapAdapter):
    def __init__(self, code: int, non_fatal_exit_codes: tuple[int, ...] = ()):
        self._code = code
        self.non_fatal_exit_codes = non_fatal_exit_codes

    def build_command(self, target, params):
        return ["python3", "-c", f"import sys; print('out'); sys.exit({self._code})"]

    async def parse_output(self, raw_stdout, target, context=None):
        if False:
            yield


def test_job_status_has_exit_code_field():
    from uuid import uuid4

    from ether.schemas.power import JobStatus, JobStatusEnum

    j_default = JobStatus(job_id=uuid4(), session_id=uuid4(), tool_name="nmap", status=JobStatusEnum.RUNNING)
    assert j_default.exit_code is None

    j_with_code = JobStatus(
        job_id=uuid4(), session_id=uuid4(), tool_name="nmap", status=JobStatusEnum.FAILED, exit_code=2
    )
    assert j_with_code.exit_code == 2


def test_executor_implements_command_runner_protocol():
    from ether.core.session import CommandRunner

    executor = Executor()
    assert isinstance(executor, CommandRunner)


@pytest.mark.asyncio
async def test_executor_raises_on_nonzero_exit_and_records_exit_code():
    executor = Executor()
    target = NetworkHost.create(ip="127.0.0.1")
    adapter = _ExitCodeAdapter(code=2)

    with pytest.raises(RuntimeError, match="exit code 2"):
        async for _ in executor.run(adapter, target, {}, task_id="t-nonzero", cwd="."):
            pass

    assert executor.get_exit_code("t-nonzero") == 2


@pytest.mark.asyncio
async def test_executor_allows_non_fatal_exit_codes():
    executor = Executor()
    target = NetworkHost.create(ip="127.0.0.1")
    adapter = _ExitCodeAdapter(code=1, non_fatal_exit_codes=(1,))

    async for _ in executor.run(adapter, target, {}, task_id="t-nonfatal", cwd="."):
        pass

    assert executor.get_exit_code("t-nonfatal") == 1


@pytest.mark.asyncio
async def test_executor_skips_internal_spooler_when_on_output_provided(tmp_path):
    executor = Executor()
    target = NetworkHost.create(ip="127.0.0.1")
    adapter = _ExitCodeAdapter(code=0)
    log_path = tmp_path / "should_not_spool.log"
    seen: list[str] = []

    async def on_out(chunk: str) -> None:
        seen.append(chunk)

    async for _ in executor.run_tool(
        adapter, target, {}, task_id="t-nospool", on_output=on_out, log_file_path=str(log_path)
    ):
        pass

    assert any("out" in c for c in seen)
    assert not log_path.exists()
