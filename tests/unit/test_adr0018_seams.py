"""Tests for ADR 0018 Pre-Epoch 4 seams: sealing, origin identity, audit trail, and CLI symmetry."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ether.common.forensic_log import ForensicLogManager
from ether.config import EtherSettings
from ether.gateway.gate import ActionGateway
from ether.graph.store import GraphStore
from ether.registry.registry import ToolRegistry
from ether.schemas.web import WebEndpoint


@pytest.mark.asyncio
async def test_close_session_uses_external_signing_key_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GraphStore.close_session uses ETHER_AUDIT_SIGNING_KEY and verify_session_seal fails closed."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_file = tmp_path / "ext_signing.key"
    key_file.write_bytes(priv_raw)
    monkeypatch.setenv("ETHER_AUDIT_SIGNING_KEY", str(key_file))

    data_dir = tmp_path / "data"
    settings = EtherSettings.load(data_dir=str(data_dir))
    store = GraphStore(str(tmp_path / "g.db"), settings=settings)
    await store.initialize()
    try:
        ws = await store.create_workspace("WS")
        sid = await store.create_session(ws, "SealTest")
        await store.close_session(sid)

        ok, msg = await store.verify_session_seal(sid, public_key=pub_raw, require_trusted_key=True)
        assert ok, msg

        receipt_path = ForensicLogManager.get_session_dir(sid, str(data_dir)) / "seal_receipt.json"
        receipt_path.unlink()
        ok_after, _ = await store.verify_session_seal(
            sid, public_key=pub_raw, require_trusted_key=True
        )
        assert not ok_after
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_anchored_identity_ignores_same_origin_paths_but_detects_port_or_host_change() -> (
    None
):
    """Same (host_ip, port) URL paths stay confirmed; port/host shifts emit anchored_identity."""
    store = GraphStore(":memory:")
    await store.initialize()
    try:
        ws = await store.create_workspace("OriginWS")
        sid = await store.create_session(ws, "OriginSess")
        fav = "a" * 64

        ep_root = WebEndpoint.create(
            url="http://16.179.220.153/",
            host_ip="16.179.220.153",
            port=80,
            favicon_hash=fav,
            anchor_hash=f"favicon:{fav}",
        )
        ep_metrics = WebEndpoint.create(
            url="http://16.179.220.153/metrics",
            host_ip="16.179.220.153",
            port=80,
            favicon_hash=fav,
            anchor_hash=f"favicon:{fav}",
        )
        ep_ftp = WebEndpoint.create(
            url="http://16.179.220.153/ftp",
            host_ip="16.179.220.153",
            port=80,
            favicon_hash=fav,
            anchor_hash=f"favicon:{fav}",
        )
        n1 = await store.upsert_finding(sid, ep_root)
        n2 = await store.upsert_finding(sid, ep_metrics)
        n3 = await store.upsert_finding(sid, ep_ftp)

        assert await store.get_anchored_migrations(sid) == []
        for nid in (n1, n2, n3):
            node = await store.get_node(sid, nid)
            assert node is not None and node["status"] == "confirmed"

        # Port change on same host IS a service migration
        ep_8080 = WebEndpoint.create(
            url="http://16.179.220.153:8080/",
            host_ip="16.179.220.153",
            port=8080,
            favicon_hash=fav,
            anchor_hash=f"favicon:{fav}",
        )
        await store.upsert_finding(sid, ep_8080)
        migrations = await store.get_anchored_migrations(sid)
        assert len(migrations) >= 1
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_gateway_propagates_data_dir_and_verify_audit_fails_on_unmanifested_logs(
    tmp_path: Path,
) -> None:
    """ActionGateway.create_session propagates data_dir; unmanifested spool logs fail verify-audit."""
    data_dir = tmp_path / "data"
    settings = EtherSettings.load(data_dir=str(data_dir))
    store = GraphStore(str(tmp_path / "g.db"), settings=settings)
    await store.initialize()
    try:
        reg = ToolRegistry()
        reg.load_tools()
        gw = ActionGateway(reg, store)
        exec_sess = gw.create_session()
        assert exec_sess.data_dir == str(data_dir)
        await exec_sess.shutdown()
    finally:
        await store.close()

    # Empty session without logs -> valid=True, empty
    ok_empty, entries_empty = ForensicLogManager.verify_session_audit("sess-empty", str(data_dir))
    assert ok_empty and entries_empty == []

    # Unmanifested .log file -> fail closed
    sess_dir = ForensicLogManager.get_session_dir("sess-unmanifested", str(data_dir))
    sess_dir.mkdir(parents=True, exist_ok=True)
    (sess_dir / "act1.log").write_text("rogue log\n", encoding="utf-8")
    ok_unman, _ = ForensicLogManager.verify_session_audit("sess-unmanifested", str(data_dir))
    assert not ok_unman


def test_cli_report_status_ps_accept_dash_s_and_reject_conflicts(tmp_path: Path) -> None:
    """ether report, status, and ps accept -s <session_id> and reject conflicting dual IDs."""
    data_dir = str(tmp_path / "cli_data")
    db_path = f"{data_dir}/ether.db"
    base = [sys.executable, "-m", "ether.cli", "--data-dir", data_dir, "--db", db_path]

    res_c = subprocess.run(
        [*base, "session", "create", "sym-test", "-j"],
        capture_output=True,
        text=True,
        check=True,
    )
    sid = json.loads(res_c.stdout)["session_id"]

    for sub in ("report", "status", "ps"):
        r = subprocess.run(
            [*base, sub, "-s", sid, "-j"], capture_output=True, text=True, check=False
        )
        assert r.returncode == 0, f"{sub} -s failed: {r.stderr}"
        assert sid in r.stdout

    r_conflict = subprocess.run(
        [*base, "report", sid, "-s", "other-id"], capture_output=True, text=True, check=False
    )
    assert r_conflict.returncode != 0
