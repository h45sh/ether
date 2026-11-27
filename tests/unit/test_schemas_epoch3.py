"""Unit tests for Epoch 3 Tier 2 Domain Finding Schemas (Database, Cloud, WebParameter)."""

import pytest

from ether.graph.store import GraphStore
from ether.schemas.cloud import CloudAsset
from ether.schemas.database import DatabaseService
from ether.schemas.web import WebParameter


@pytest.mark.fast
def test_database_service_creation_and_pik():
    db = DatabaseService.create(
        host_ip="192.168.1.100",
        port=3306,
        db_type="MySQL",
        version="8.0.28",
        auth_required=True,
        banner="8.0.28-0ubuntu0.20.04.3",
        databases=["users", "orders"],
    )

    assert db.schema_type == "database.service"
    assert db.pik == {"host_ip": "192.168.1.100", "port": 3306, "db_type": "mysql"}
    assert db.parent is not None
    assert db.parent.target_type == "network.host"
    assert db.parent.target_pik == {"ip": "192.168.1.100"}
    assert db.data["version"] == "8.0.28"
    assert "mysql database on 192.168.1.100:3306" in db.to_semantic_text().lower()


@pytest.mark.fast
def test_cloud_asset_creation_and_pik():
    asset = CloudAsset.create(
        provider="AWS",
        resource_id="corp-financial-backups-2026",
        service="s3",
        public_access=True,
        region="us-east-1",
        url="https://corp-financial-backups-2026.s3.amazonaws.com",
    )

    assert asset.schema_type == "cloud.asset"
    assert asset.pik == {"provider": "aws", "resource_id": "corp-financial-backups-2026"}
    assert asset.data["public_access"] is True
    assert "publicly accessible" in asset.to_semantic_text().lower()


@pytest.mark.fast
def test_web_parameter_creation_and_pik():
    param = WebParameter.create(
        endpoint_url="https://api.example.com/v1/search",
        param_name="query",
        method="get",
        param_type="query",
        reflection=True,
        sample_value="test_payload",
    )

    assert param.schema_type == "web.parameter"
    assert param.pik == {
        "endpoint_url": "https://api.example.com/v1/search",
        "param_name": "query",
        "method": "GET",
    }
    assert param.parent is not None
    assert param.parent.target_type == "web.endpoint"
    assert param.data["reflection"] is True
    assert "reflected" in param.to_semantic_text().lower()


@pytest.mark.fast
def test_deterministic_pik_equality():
    # Two findings with identical inputs must generate identical SHA-256 node IDs
    store = GraphStore(":memory:")
    db1 = DatabaseService.create(
        host_ip="10.0.0.1", port=5432, db_type="PostgreSQL", version="15.1"
    )
    db2 = DatabaseService.create(
        host_ip="10.0.0.1", port=5432, db_type="postgresql", version="15.1"
    )
    assert store.generate_node_id(db1.schema_type, db1.pik) == store.generate_node_id(
        db2.schema_type, db2.pik
    )

    c1 = CloudAsset.create(provider="GCP", resource_id="my-bucket")
    c2 = CloudAsset.create(provider="gcp", resource_id="my-bucket")
    assert store.generate_node_id(c1.schema_type, c1.pik) == store.generate_node_id(
        c2.schema_type, c2.pik
    )

    p1 = WebParameter.create(
        endpoint_url="https://target.com/login", param_name="user", method="post"
    )
    p2 = WebParameter.create(
        endpoint_url="https://target.com/login", param_name="user", method="POST"
    )
    assert store.generate_node_id(p1.schema_type, p1.pik) == store.generate_node_id(
        p2.schema_type, p2.pik
    )
