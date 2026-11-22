"""Unit tests for VectorEmbeddingEngine and Finding Semantic Serialization."""

import math

import pytest

from ether.common.embeddings import VectorEmbeddingEngine, get_embedding_engine
from ether.schemas.base import BaseFinding
from ether.schemas.credential import CredentialFound
from ether.schemas.dns import DnsRecord
from ether.schemas.network import NetworkHost, NetworkService, TLSCertificate
from ether.schemas.vulnerability import ExploitReference, VulnerabilityFound
from ether.schemas.web import WebEndpoint, WebTechnology


@pytest.mark.fast
def test_vector_embedding_engine_properties():
    engine = VectorEmbeddingEngine()
    assert engine.dimension == 384

    # Test empty text
    empty_vec = engine.embed_text("")
    assert len(empty_vec) == 384
    assert empty_vec[0] == 1.0
    assert sum(x * x for x in empty_vec) == pytest.approx(1.0)

    # Test text embedding
    text = "Apache HTTP Server 2.4.49 path traversal vulnerability CVE-2021-41773"
    vec = engine.embed_text(text)
    assert len(vec) == 384

    # Unit normalization: ||v||_2 = 1.0
    norm = math.sqrt(sum(x * x for x in vec))
    assert norm == pytest.approx(1.0, rel=1e-5)

    # Determinism
    vec2 = engine.embed_text(text)
    assert vec == vec2

    # Batch embedding
    batch = engine.embed_batch([text, "open port 80 http"])
    assert len(batch) == 2
    assert batch[0] == vec
    assert len(batch[1]) == 384
    assert math.sqrt(sum(x * x for x in batch[1])) == pytest.approx(1.0, rel=1e-5)


@pytest.mark.fast
def test_vector_engine_semantic_similarity():
    engine = get_embedding_engine()

    text_web_1 = "Apache HTTP Server version 2.4.49 web server running on port 80"
    text_web_2 = "Nginx web server reverse proxy running on port 80"
    text_ssh = "OpenSSH 8.2p1 Debian secure shell daemon on port 22"

    v_web1 = engine.embed_text(text_web_1)
    v_web2 = engine.embed_text(text_web_2)
    v_ssh = engine.embed_text(text_ssh)

    # Self similarity is 1.0
    assert engine.cosine_similarity(v_web1, v_web1) == pytest.approx(1.0, rel=1e-5)

    sim_web = engine.cosine_similarity(v_web1, v_web2)
    sim_ssh = engine.cosine_similarity(v_web1, v_ssh)

    # Web servers should be more similar to each other than to SSH
    assert sim_web > sim_ssh


@pytest.mark.fast
def test_finding_to_semantic_text():
    # 1. BaseFinding fallback
    base = BaseFinding(schema_type="custom.finding", pik={"id": "abc"}, data={"foo": "bar"})
    sem_base = base.to_semantic_text()
    assert "custom.finding: id=abc" in sem_base
    assert "foo=bar" in sem_base

    # 2. NetworkHost
    host = NetworkHost.create(ip="192.168.1.50", hostname="target.local", os="Linux Ubuntu 22.04")
    sem_host = host.to_semantic_text()
    assert "Discovered Host IP: 192.168.1.50" in sem_host
    assert "Linux Ubuntu 22.04" in sem_host
    assert "target.local" in sem_host

    # 3. NetworkService
    svc = NetworkService.create(
        host_ip="192.168.1.50",
        port=443,
        protocol="tcp",
        service_name="https",
        banner="nginx/1.18.0",
    )
    sem_svc = svc.to_semantic_text()
    assert "https service on 192.168.1.50:443/tcp" in sem_svc
    assert "nginx/1.18.0" in sem_svc

    # 4. TLSCertificate
    tls = TLSCertificate.create(host_ip="192.168.1.50", port=443, fingerprint="a" * 64)
    sem_tls = tls.to_semantic_text()
    assert "TLS Certificate" in sem_tls
    assert "192.168.1.50:443" in sem_tls

    # 5. WebEndpoint
    endpoint = WebEndpoint.create(
        url="https://example.com/admin/login", status_code=200, title="Admin Portal", server="nginx"
    )
    sem_endpoint = endpoint.to_semantic_text()
    assert "Web Endpoint at https://example.com/admin/login" in sem_endpoint
    assert "Admin Portal" in sem_endpoint

    # 6. WebTechnology
    tech = WebTechnology.create(
        url="https://example.com",
        technology_name="React",
        version="18.2.0",
        categories=["UI Frameworks"],
    )
    sem_tech = tech.to_semantic_text()
    assert "Web Technology 'React'" in sem_tech
    assert "Version: 18.2.0" in sem_tech
    assert "UI Frameworks" in sem_tech

    # 7. VulnerabilityFound
    vuln = VulnerabilityFound.create(
        host_ip="192.168.1.50",
        vuln_id="CVE-2021-44228",
        port=8080,
        severity="CRITICAL",
        title="Log4Shell RCE",
    )
    sem_vuln = vuln.to_semantic_text()
    assert "Vulnerability CVE-2021-44228" in sem_vuln
    assert "192.168.1.50" in sem_vuln
    assert "Port 8080" in sem_vuln
    assert "CRITICAL" in sem_vuln
    assert "Log4Shell RCE" in sem_vuln

    # 8. ExploitReference
    exp = ExploitReference.create(
        exploit_id="EDB-50592",
        title="Log4j Remote Code Execution",
        cve_id="CVE-2021-44228",
        platform="java",
    )
    sem_exp = exp.to_semantic_text()
    assert "Exploit Reference EDB-50592" in sem_exp
    assert "Log4j Remote Code Execution" in sem_exp
    assert "CVE-2021-44228" in sem_exp

    # 9. CredentialFound
    cred = CredentialFound.create(context="ssh", username="root", host_ip="192.168.1.50")
    sem_cred = cred.to_semantic_text()
    assert "Credential discovered for user 'root'" in sem_cred
    assert "context 'ssh'" in sem_cred

    # 10. DnsRecord
    dns = DnsRecord.create(
        domain="api.example.com",
        record_type="A",
        value="192.168.1.100",
        resolved_ip="192.168.1.100",
    )
    sem_dns = dns.to_semantic_text()
    assert "DNS Record: api.example.com A 192.168.1.100" in sem_dns
