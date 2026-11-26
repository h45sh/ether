"""Adversarial security boundary test suite for Epoch 3, Section 8 (ADR 0016)."""

from __future__ import annotations

import asyncio
import base64
import sqlite3
import textwrap
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ether.common.forensic_log import ForensicLogManager
from ether.common.scope import EngagementScope
from ether.common.session_sealer import SealState, SessionSealer
from ether.common.transport import PinnedTransport, SSRFPinnedError
from ether.core.privilege import PrivilegeGovernor
from ether.gateway.flags import FlagFirewall, FlagFirewallError
from ether.gateway.gate import GatePolicy
from ether.graph.crypto import CryptoEngine, is_credential_expired, zeroize_bytes
from ether.graph.store import GraphStore
from ether.mcp.security import LeakyBucketRateLimiter, OperationType, SecurityMiddleware
from ether.registry.loader import PluginLoader, PluginSecurityError, PluginTrustMode
from ether.registry.registry import ToolRegistry
from ether.schemas.credential import CredentialFound
from ether.schemas.network import NetworkHost


@pytest.mark.asyncio
@pytest.mark.fast
async def test_write_queue_exact_ownership_with_duplicate_piks():
    """Coalesced batch upserts with overlapping PIKs must return exact per-caller node IDs."""
    store = GraphStore(":memory:")
    await store.initialize()
    ws = await store.create_workspace("WQ-WS")
    sess = await store.create_session(ws, "WQ-Sess")

    f1 = [NetworkHost.create(ip="10.10.10.1"), NetworkHost.create(ip="10.10.10.2")]
    f2 = [NetworkHost.create(ip="10.10.10.2"), NetworkHost.create(ip="10.10.10.3")]

    res1, res2 = await asyncio.gather(
        store.upsert_findings_batch(sess, f1),
        store.upsert_findings_batch(sess, f2),
    )

    assert len(res1) == 2
    assert len(res2) == 2
    assert res1[1] == res2[0]  # Shared PIK 10.10.10.2 resolves to identical node ID
    assert res1[0] != res2[1]
    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_session_sealer_ed25519_tamper_detection(tmp_path: Path):
    """SessionSealer produces verifiable Ed25519 receipts and detects audit tampering."""
    db_path = tmp_path / "ether.db"
    store = GraphStore(str(db_path))
    await store.initialize()
    ws = await store.create_workspace("SealWS")
    sess = await store.create_session(ws, "SealSess")

    spooler, log_path = ForensicLogManager.open_action_spool(
        sess, "act-1", "nmap", "10.0.0.1", data_dir=str(tmp_path)
    )
    spooler.write("PORT 80/tcp open http\n")
    spooler.close()
    ForensicLogManager.record_action_completion(
        sess, "act-1", "nmap", "10.0.0.1", 0, log_path, data_dir=str(tmp_path)
    )

    sealer = SessionSealer(store=store, data_dir=tmp_path)
    receipt = await sealer.seal_session(sess)
    assert receipt.state == SealState.SEALED.value
    assert sealer.get_seal_state(sess) == SealState.SEALED

    ok, msg = SessionSealer.verify_seal(sess, data_dir=tmp_path)
    assert ok, msg

    # Tamper with audit manifest
    manifest_path = ForensicLogManager.get_manifest_path(sess, data_dir=str(tmp_path))
    manifest_path.write_text(manifest_path.read_text() + '{"tampered":true}\n', encoding="utf-8")
    ok_after, _ = SessionSealer.verify_seal(sess, data_dir=tmp_path)
    assert not ok_after
    await store.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_crypto_engine_encrypts_credentials_at_rest(tmp_path: Path):
    """CryptoEngine encrypts CredentialFound passwords in SQLite and zeroizes memory."""
    db_path = tmp_path / "enc.db"
    store = CryptoEngine.open_encrypted_store(db_path, passphrase_or_key=b"k" * 32, data_dir=tmp_path)
    await store.initialize()
    ws = await store.create_workspace("EncWS")
    sess = await store.create_session(ws, "EncSess")

    cred = CredentialFound.create(
        context="ssh://10.0.0.5",
        username="admin",
        password="SuperSecretPassword123!",
    )
    nid = await store.upsert_finding(sess, cred)

    # Raw SQLite file must not contain plaintext password
    conn = sqlite3.connect(str(db_path))
    raw_row = conn.execute("SELECT data_json FROM nodes WHERE id = ?", (nid,)).fetchone()
    conn.close()
    assert raw_row is not None
    assert "SuperSecretPassword123!" not in raw_row[0]
    assert "enc:chacha20v1:" in raw_row[0]

    # Transparent decryption through GraphStore
    node = await store.get_node(sess, nid)
    assert node is not None
    assert node["data"]["password"] == "SuperSecretPassword123!"

    # Memory zeroization & TTL check
    buf = bytearray(b"sensitive-secret")
    zeroize_bytes(buf)
    assert buf == bytearray(len(buf))
    assert is_credential_expired({"ttl_expires_at": time.time() - 5})
    assert not is_credential_expired({"ttl_expires_at": time.time() + 60})
    await store.close()


@pytest.mark.fast
def test_flag_firewall_safe_vs_unrestricted():
    """FlagFirewall blocks dangerous/compound flags under SAFE and allows them under UNRESTRICTED."""
    reg = ToolRegistry()
    reg.load_tools()
    fw = FlagFirewall(registry=reg)

    # Shell metacharacters blocked under ALL policies
    for pol in (GatePolicy.SAFE, GatePolicy.UNRESTRICTED):
        with pytest.raises(FlagFirewallError):
            fw.validate_arguments("nmap", ["-sV", ";id"], pol)

    # Dangerous flags blocked under SAFE, allowed under UNRESTRICTED
    with pytest.raises(FlagFirewallError):
        fw.validate_arguments("nmap", ["--script=vuln"], GatePolicy.SAFE)

    unrestricted_args = fw.validate_arguments("nmap", ["--script=vuln"], GatePolicy.UNRESTRICTED)
    assert unrestricted_args == ["--script=vuln"]

    safe_args = fw.validate_arguments("nmap", ["-sV", "-Pn"], GatePolicy.SAFE)
    assert safe_args == ["-sV", "-Pn"]


@pytest.mark.asyncio
@pytest.mark.fast
async def test_mcp_security_middleware_rbac_cors_and_rate_limit():
    """SecurityMiddleware enforces HMAC scopes, CORS origins, and leaky-bucket rate limits."""
    limiter = LeakyBucketRateLimiter(capacity=3, refill_per_sec=0.0)
    mw = SecurityMiddleware(
        signing_secret="super-secret-key",
        allowed_origins=["https://console.local"],
        rate_limiter=limiter,
    )

    read_token = mw.issue_token("agent-ro", [OperationType.TELEMETRY_READ])
    ctx = await mw.authenticate_request(
        headers={"Authorization": f"Bearer {read_token}", "Origin": "https://console.local"},
        client_cert=None,
        operation=OperationType.TELEMETRY_READ,
        client_ip="10.0.0.1",
    )
    assert ctx.subject == "agent-ro"

    # Insufficient scope -> 403
    with pytest.raises(PermissionError) as exc_info:
        await mw.authenticate_request(
            headers={"Authorization": f"Bearer {read_token}"},
            client_cert=None,
            operation=OperationType.TOOL_EXECUTE,
            client_ip="10.0.0.1",
        )
    assert getattr(exc_info.value, "status_code", None) == 403

    # CORS violation -> 403
    with pytest.raises(PermissionError) as cors_exc:
        await mw.authenticate_request(
            headers={"Authorization": f"Bearer {read_token}", "Origin": "https://evil.example"},
            client_cert=None,
            operation=OperationType.TELEMETRY_READ,
            client_ip="10.0.0.1",
        )
    assert getattr(cors_exc.value, "status_code", None) == 403

    # 4th request from same IP trips rate limit -> 429
    with pytest.raises(PermissionError) as rl_exc:
        await mw.authenticate_request(
            headers={"Authorization": f"Bearer {read_token}"},
            client_cert=None,
            operation=OperationType.TELEMETRY_READ,
            client_ip="10.0.0.1",
        )
    assert getattr(rl_exc.value, "status_code", None) == 429


@pytest.mark.fast
def test_plugin_loader_ed25519_and_ast_sandbox(tmp_path: Path):
    """PluginLoader verifies Ed25519 signatures and rejects eval/exec in adapter AST."""
    tool_dir = tmp_path / "signed_tool"
    tool_dir.mkdir()
    manifest_path = tool_dir / "manifest.toml"
    adapter_path = tool_dir / "adapter.py"

    manifest_path.write_text(
        textwrap.dedent("""
            [meta]
            name = "signed_tool"
            description = "Signed test adapter"
            categories = ["testing"]
            [input]
            accepts = ["network.host"]
            [output]
            produces = ["network.service"]
        """),
        encoding="utf-8",
    )
    adapter_path.write_text(
        textwrap.dedent("""
            from ether.registry.adapter import ToolAdapter
            class SignedAdapter(ToolAdapter):
                def validate_install(self) -> bool: return True
                def build_command(self, target, params): return ["echo"]
                async def parse_output(self, raw_stdout, target, context=None):
                    if False: yield
        """),
        encoding="utf-8",
    )

    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    digest = PluginLoader.compute_bundle_digest(adapter_path, manifest_path)
    sig_b64 = base64.b64encode(priv.sign(digest)).decode("ascii")
    adapter_path.with_suffix(".py.sig").write_text(sig_b64, encoding="utf-8")

    import hashlib

    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    loader = PluginLoader(trust_mode=PluginTrustMode.STRICT, trusted_public_keys=[pub_bytes])
    adapter = loader.load_verified_adapter(adapter_path, manifest_path, expected_manifest_sha256=manifest_sha)
    assert adapter.validate_install() is True

    # AST rejection of eval() even in DEV mode
    adapter_path.write_text(
        "from ether.registry.adapter import ToolAdapter\nx = eval('1+1')\n",
        encoding="utf-8",
    )
    dev_loader = PluginLoader(trust_mode=PluginTrustMode.DEV)
    with pytest.raises(PluginSecurityError):
        dev_loader.load_verified_adapter(adapter_path, manifest_path)


@pytest.mark.asyncio
@pytest.mark.fast
async def test_pinned_transport_blocks_rebinding_to_imds(monkeypatch):
    """PinnedTransport blocks connections when DNS resolves to cloud metadata or loopback."""
    import socket

    async def _rebinding_getaddrinfo(self, host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(asyncio.AbstractEventLoop, "getaddrinfo", _rebinding_getaddrinfo)
    scope = EngagementScope(allow_loopback=False)
    async with PinnedTransport.create_client(scope=scope) as client:
        with pytest.raises(SSRFPinnedError):
            await client.get("http://rebind.attacker.example/latest/meta-data/")


@pytest.mark.fast
def test_privilege_governor_isolated_command_builder():
    """PrivilegeGovernor builds isolated UDS worker command cleanly."""
    cmd = PrivilegeGovernor.build_isolated_worker_command(
        ["nmap", "-sV", "10.0.0.1"], uds_path=Path("/run/ether/worker.sock")
    )
    assert cmd[:3] == ["ether-worker", "--socket", "/run/ether/worker.sock"]
    assert cmd[4:] == ["nmap", "-sV", "10.0.0.1"]
