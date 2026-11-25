"""Unit tests for cryptographic TLS schemas, native async prober, and sslyze adapter."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ether.schemas.network import (
    NetworkService,
    TlsCertificate,
    TlsCipherSuite,
)


@pytest.mark.fast
def test_tls_certificate_and_cipher_suite_schemas():
    """Verify TLS finding schemas generate deterministic PIKs and relationships."""
    cert = TlsCertificate.create(
        fingerprint="a" * 64,
        host_ip="192.168.1.1",
        port=443,
        subject="CN=example.com",
    )
    assert cert.schema_type == "tls.certificate"
    assert cert.pik == {"fingerprint": "a" * 64}
    assert cert.parent.target_type == "network.service"
    assert cert.anchor_hash == f"tls:{'a' * 64}"
    assert "TLS Certificate" in cert.to_semantic_text()

    cipher = TlsCipherSuite.create(
        host_ip="192.168.1.1",
        port=443,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        protocol_version="TLSv1.3",
        deprecated=False,
    )
    assert cipher.schema_type == "tls.cipher_suite"
    assert cipher.pik == {
        "host_ip": "192.168.1.1",
        "port": 443,
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
    }
    assert cipher.parent.target_type == "network.service"
    assert "tlsv1.3" in cipher.to_semantic_text().lower()


@pytest.mark.asyncio
async def test_native_tls_probe_adapter():
    """Verify native zero-fork Tier A async TLS probe extracts cert and cipher findings."""
    from tools.tls_probe.adapter import TlsProbeAdapter

    adapter = TlsProbeAdapter()
    assert adapter.execution_tier == "coroutine"
    assert adapter.validate_install() is True

    target = NetworkService.create(host_ip="127.0.0.1", port=443)

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = b"\x30\x82\x01\x0a" + b"\x00" * 50
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_writer.get_extra_info = MagicMock(
        side_effect=lambda key: {
            "ssl_object": mock_ssl_obj,
            "cipher": ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128),
        }.get(key)
    )

    mock_context = AsyncMock()
    mock_context.policy = "unrestricted"

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
        mock_open.return_value = (AsyncMock(), mock_writer)
        with patch("ether.common.scope.ScopeValidator.check_destination") as mock_check:
            from ether.common.scope import ScopeVerdict

            mock_check.return_value = ScopeVerdict(allowed=True, reason="ALLOWED", normalized_target="127.0.0.1")
            findings = []
            async for f in adapter.execute_action(target, {}, mock_context):
                findings.append(f)

            assert len(findings) >= 2
            cert_findings = [f for f in findings if f.schema_type == "tls.certificate"]
            cipher_findings = [f for f in findings if f.schema_type == "tls.cipher_suite"]

            assert len(cert_findings) == 1
            assert len(cipher_findings) == 1
            assert cipher_findings[0].data["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"
