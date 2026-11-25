import pytest

from ether.schemas.network import NetworkHost
from tools.nmap.adapter import NmapAdapter


@pytest.fixture
def adapter():
    return NmapAdapter()


def test_nmap_build_command(adapter):
    target = NetworkHost.create(ip="192.168.1.10")

    # 1. Standard command build
    cmd = adapter.build_command(target, {})
    assert "-oX" in cmd
    assert "-" in cmd
    assert "192.168.1.10" in cmd

    # 2. Command build with raw flags
    cmd_flags = adapter.build_command(target, {"raw_flags": "-sV -Pn -p 80,443"})
    assert "-sV" in cmd_flags
    assert "-Pn" in cmd_flags
    assert "192.168.1.10" in cmd_flags

    # 3. Target missing IP with no flags raises ValueError
    empty_target = NetworkHost.create(ip="")
    empty_target.pik = {}
    with pytest.raises(ValueError, match="Target finding must have an IP address"):
        adapter.build_command(empty_target, {})


@pytest.mark.asyncio
async def test_nmap_parse_output(adapter):
    sample_output = """
Starting Nmap 7.93 ( https://nmap.org ) at 2026-08-26 12:00 UTC
Nmap scan report for 192.168.1.50
Host is up (0.00045s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    Apache 2.4.41
443/tcp  open  https   nginx 1.18.0

Nmap scan report for host.example.com (10.0.0.5)
Host is up (0.00021s latency).
PORT     STATE SERVICE VERSION
8080/tcp open  http-proxy

Nmap done: 2 IP addresses (2 hosts up) scanned in 1.23 seconds
"""
    target = NetworkHost.create(ip="192.168.1.50")
    findings = []
    async for f in adapter.parse_output(sample_output, target):
        findings.append(f)

    # 2 hosts + 4 services = 6 findings
    assert len(findings) == 6

    hosts = [f for f in findings if f.schema_type == "network.host"]
    services = [f for f in findings if f.schema_type == "network.service"]

    assert len(hosts) == 2
    assert hosts[0].pik["ip"] == "192.168.1.50"
    assert hosts[1].pik["ip"] == "10.0.0.5"

    assert len(services) == 4

    # Check individual services
    s1 = next(s for s in services if s.pik["port"] == 22)
    assert s1.pik["host_ip"] == "192.168.1.50"
    assert s1.pik["protocol"] == "tcp"
    assert s1.data["service_name"] == "ssh"

    s2 = next(s for s in services if s.pik["port"] == 80)
    assert s2.pik["host_ip"] == "192.168.1.50"
    assert s2.data["service_name"] == "http"

    s3 = next(s for s in services if s.pik["port"] == 443)
    assert s3.pik["host_ip"] == "192.168.1.50"
    assert s3.data["service_name"] == "https"

    s4 = next(s for s in services if s.pik["port"] == 8080)
    assert s4.pik["host_ip"] == "10.0.0.5"
    assert s4.data["service_name"] == "http-proxy"


@pytest.mark.asyncio
async def test_nmap_parse_xml_with_firewall_reasons(adapter):
    xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.93">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="echo-reply"/>
<address addr="10.0.1.15" addrtype="ipv4"/>
<ports>
<extraports state="filtered" count="997">
<extrareasons reason="no-response" count="997" proto="tcp"/>
</extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="filtered" reason="admin-prohibited"/><service name="https"/></port>
<port protocol="tcp" portid="3306"><state state="closed" reason="reset"/><service name="mysql"/></port>
</ports>
</host>
</nmaprun>"""

    target = NetworkHost.create(ip="10.0.1.15")

    # 1. By default, closed and filtered ports are excluded from NetworkService findings
    default_findings = [f async for f in adapter.parse_output(xml_output, target)]
    default_svcs = [f for f in default_findings if f.schema_type == "network.service"]
    assert len(default_svcs) == 1
    assert default_svcs[0].pik["port"] == 22
    assert default_svcs[0].data["firewall_reason"] == "allowed"

    # 2. When include_all_states=True, all states are extracted for firewall analysis
    findings = []
    async for f in adapter.parse_output(xml_output, target, context={"include_all_states": True}):
        findings.append(f)

    hosts = [f for f in findings if f.schema_type == "network.host"]
    services = [f for f in findings if f.schema_type == "network.service"]

    assert len(hosts) == 1
    assert hosts[0].pik["ip"] == "10.0.1.15"
    assert len(services) == 4

    ssh_svc = next(s for s in services if s.pik["port"] == 22)
    assert ssh_svc.data["firewall_reason"] == "allowed"

    http_svc = next(s for s in services if s.pik["port"] == 80)
    assert http_svc.data["firewall_reason"] == "stateful_drop"

    https_svc = next(s for s in services if s.pik["port"] == 443)
    assert https_svc.data["firewall_reason"] == "stateless_filter"

    mysql_svc = next(s for s in services if s.pik["port"] == 3306)
    assert mysql_svc.data["firewall_reason"] == "host_reject"
