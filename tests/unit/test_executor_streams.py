"""Unit tests for stream normalization and curses de-escaping in Executor and LogSpooler."""

import asyncio
from typing import Any, AsyncIterator, Dict

import pytest

from ether.core.executor import LogSpooler
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost


class MockProgressAdapter(ToolAdapter):
    """Mock adapter simulating interactive tools that emit \\r progress bars and ANSI sequences."""

    name = "mock_progress"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> list[str]:
        return ["echo", "mock"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        if "Found host:" in raw_stdout:
            ip = raw_stdout.split("Found host:")[1].strip()
            yield NetworkHost.create(ip=ip)


@pytest.mark.fast
def test_log_spooler_ansi_and_carriage_return_collapse(tmp_path):
    log_file = tmp_path / "test_spooler.log"
    spooler = LogSpooler(str(log_file))

    # Write ANSI escape sequences and carriage return overwrites
    spooler.write("\x1b[32m[+] Starting scan...\x1b[0m\n")
    spooler.write("Progress: 10%\rProgress: 50%\rProgress: 100%\n")
    spooler.write("Intermediate \rFinal result\n")
    spooler.close()

    content = log_file.read_text()
    assert "\x1b[" not in content
    assert "[+] Starting scan...\n" in content
    assert "Progress: 100%\n" in content
    assert "Progress: 10%" not in content
    assert "Progress: 50%" not in content
    assert "Final result\n" in content
    assert "Intermediate" not in content


@pytest.mark.asyncio
async def test_drain_stream_collapses_carriage_returns_and_parses():
    adapter = MockProgressAdapter()
    target = NetworkHost.create(ip="127.0.0.1")

    # Simulate a stream yielding noisy progress bars followed by findings
    stream = asyncio.StreamReader()
    stream.feed_data(
        b"\x1b[33mScanning [==    ] 20%\r\x1b[33mScanning [====  ] 50%\r\x1b[32mFound host: 192.168.1.100\n"
    )
    stream.feed_data(b"Progress: 99%\rFound host: 192.168.1.200\n")
    stream.feed_eof()

    finding_queue = asyncio.Queue()
    parsing_context = {}
    spooler = LogSpooler(None)

    # Replicate _drain_stream logic
    buffer = ""
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        raw_text = chunk.decode(errors="replace")
        spooler.write(raw_text)

        from ether.common import strip_ansi

        cleaned = strip_ansi(raw_text).replace("\r\n", "\n")
        buffer += cleaned
        if "\n" in buffer:
            lines = buffer.split("\n")
            buffer = lines.pop()
            for line in lines:
                collapsed = line.split("\r")[-1].strip()
                if not collapsed:
                    continue
                async for finding in adapter.parse_output(
                    collapsed, target, context=parsing_context
                ):
                    await finding_queue.put(finding)

    findings = []
    while not finding_queue.empty():
        findings.append(await finding_queue.get())

    assert len(findings) == 2
    assert findings[0].pik["ip"] == "192.168.1.100"
    assert findings[1].pik["ip"] == "192.168.1.200"
