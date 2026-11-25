"""Unit tests for StreamRecoveryEngine and partial stream salvage on timeout."""

import pytest

from ether.core.recovery import (
    StreamRecoveryEngine,
    salvage_json_objects,
    salvage_ndjson_lines,
    salvage_xml_elements,
)
from ether.schemas.network import NetworkHost
from tools.ffuf.adapter import FfufAdapter
from tools.nuclei.adapter import NucleiAdapter


@pytest.mark.fast
def test_salvage_json_objects_truncated_array():
    truncated = '[{"url": "http://target/api", "status": 200}, {"url": "http://target/admin", "status": 403}, {"url": "http://target/par'
    objects = salvage_json_objects(truncated)
    assert len(objects) == 2
    assert objects[0]["url"] == "http://target/api"
    assert objects[1]["status"] == 403


@pytest.mark.fast
def test_salvage_json_objects_concatenated_and_bytes():
    stream_bytes = b'{"id": 1}{"id": 2}{"id": 3, "broken": '
    objects = StreamRecoveryEngine.salvage_json_objects(stream_bytes)
    assert len(objects) == 2
    assert [o["id"] for o in objects] == [1, 2]


@pytest.mark.fast
def test_salvage_ndjson_lines_partial_terminal():
    ndjson = '{"template-id": "t1", "info": {"name": "T1"}}\n{"template-id": "t2", "info": {"name": "T2"}}\n{"incomplete": '
    lines = salvage_ndjson_lines(ndjson)
    assert len(lines) == 2
    assert lines[0]["template-id"] == "t1"
    assert lines[1]["template-id"] == "t2"


@pytest.mark.fast
def test_salvage_xml_elements_truncated():
    xml_data = "<nmaprun><host><address addr='10.0.0.1'/></host><host><address addr='10.0.0.2'/></host><host><address "
    hosts = salvage_xml_elements(xml_data, "host")
    assert len(hosts) == 2
    assert "10.0.0.1" in hosts[0]
    assert "10.0.0.2" in hosts[1]


@pytest.mark.fast
@pytest.mark.asyncio
async def test_nuclei_salvage_truncated_stream():
    adapter = NucleiAdapter()
    target = NetworkHost.create(ip="10.0.0.1")
    damaged_stream = (
        '{"template-id": "tech-detect", "info": {"name": "Nginx", "tags": ["tech"]}, "matched-at": "http://10.0.0.1", "extracted-results": ["1.18.0"]}\n'
        '{"template-id": "broken-item", "info": {"name": "Br'
    )
    findings = []
    async for f in adapter.parse_output(damaged_stream, target):
        findings.append(f)

    assert len(findings) == 1
    assert findings[0].schema_type == "web.technology"
    assert findings[0].data["technology_name"] == "Nginx"


@pytest.mark.fast
@pytest.mark.asyncio
async def test_ffuf_salvage_truncated_json_array():
    adapter = FfufAdapter()
    target = NetworkHost.create(ip="10.0.0.1")
    damaged_ffuf_json = (
        '{"results": [{"url": "http://10.0.0.1/admin", "status": 200, "length": 500, "words": 20, "lines": 5, "input": {"FUZZ": "admin"}},'
        '{"url": "http://10.0.0.1/login", "status": 200, "length": 300, "words": 15, "lines": 3, "input": {"FUZZ": "login"}},'
        '{"url": "http://10.0.0.1/par'
    )
    findings = []
    async for f in adapter.parse_output(damaged_ffuf_json, target):
        findings.append(f)

    # Yields 2 WebEndpoints plus 1 AuditMisconfig for sensitive 'admin' endpoint
    assert len(findings) == 3
    assert any(f.data.get("url") == "http://10.0.0.1/admin" for f in findings)
    assert any(f.data.get("url") == "http://10.0.0.1/login" for f in findings)
    assert any(f.schema_type == "audit.misconfig" for f in findings)
