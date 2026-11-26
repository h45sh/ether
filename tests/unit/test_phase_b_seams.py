"""Regression tests for Phase B transport, crypto lifecycle, and supply-chain hardening."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ether.common.scope import EngagementScope
from ether.common.transport import SSRFPinnedError, _PinnedNetworkBackend
from ether.graph.crypto import ENC_PREFIX, CryptoEngine
from ether.graph.store import GraphStore
from ether.schemas.credential import CredentialFound


@pytest.mark.fast
def test_crypto_engine_key_versioning_and_rotation():
    """CryptoEngine embeds key_id, decrypts previous keys after rotation, and re-encrypts."""
    k1 = os.urandom(32)
    k2 = os.urandom(32)
    eng = CryptoEngine(key=k1)
    kid1 = eng.key_id

    enc1 = eng.encrypt_field("super-secret", aad=b"credential.found")
    assert enc1.startswith(f"{ENC_PREFIX}{kid1}:")
    assert eng.decrypt_field(enc1, aad=b"credential.found") == "super-secret"

    eng.rotate_key(k2)
    assert eng.key_id != kid1
    # Old ciphertext still decrypts via previous key
    assert eng.decrypt_field(enc1, aad=b"credential.found") == "super-secret"

    # Re-encrypt upgrades ciphertext to the new key ID
    enc2 = eng.reencrypt_field(enc1, aad=b"credential.found")
    assert enc2.startswith(f"{ENC_PREFIX}{eng.key_id}:")
    assert eng.decrypt_field(enc2, aad=b"credential.found") == "super-secret"


@pytest.mark.asyncio
@pytest.mark.fast
async def test_export_session_redacts_credentials_by_default(tmp_path):
    """GraphStore.export_session redacts sensitive credential fields by default."""
    src_db = tmp_path / "src.db"
    dst_db = tmp_path / "dst.db"

    store = GraphStore(str(src_db))
    await store.initialize()
    try:
        _, sess_id = await store.get_or_create_default_session()
        cred = CredentialFound.create(
            context="ssh://10.0.0.1",
            username="admin",
            password="plaintext-password-123",
            service="ssh",
        )
        await store.upsert_finding(sess_id, cred)
        await store.export_session(sess_id, str(dst_db))
    finally:
        await store.close()

    exported = GraphStore(str(dst_db))
    await exported.initialize()
    try:
        nodes = await exported.get_all_nodes(sess_id)
        assert len(nodes) == 1
        assert nodes[0]["data"]["password"] == "[REDACTED]"
    finally:
        await exported.close()


@pytest.mark.asyncio
@pytest.mark.fast
async def test_pinned_network_backend_verifies_peer_ip():
    """_PinnedNetworkBackend rejects connections if socket peer IP mismatches pinned IP."""
    fake_stream = MagicMock()
    fake_stream.get_extra_info.return_value = ("169.254.169.254", 80)
    fake_stream.aclose = AsyncMock()

    inner = MagicMock()
    inner.connect_tcp = AsyncMock(return_value=fake_stream)

    scope = EngagementScope(allowed_cidrs=["93.184.216.0/24"])
    backend = _PinnedNetworkBackend(scope=scope, policy_is_unrestricted=False, inner=inner)

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(
            return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]
        )
        with pytest.raises(SSRFPinnedError, match="did not match pinned IP"):
            await backend.connect_tcp("example.com", 80)

    fake_stream.aclose.assert_awaited_once()
