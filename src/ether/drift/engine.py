"""Architectural drift auditing engine and baseline serialization.

Compares observed entity graph against ground-truth baseline specifications using
deterministic Jaccard topological distance and strict attribute/version comparison.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ether.graph.store import GraphStore
from ether.schemas.vulnerability import AuditDrift


@dataclass
class DriftReport:
    """Structured report produced by architectural drift audit."""

    session_id: str
    drift_score: float
    mode: str
    discrepancies: List[AuditDrift] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to JSON-serializable dictionary."""
        return {
            "session_id": self.session_id,
            "drift_score": self.drift_score,
            "mode": self.mode,
            "summary": self.summary,
            "discrepancies": [
                {
                    "schema_type": d.schema_type,
                    "pik": d.pik,
                    "data": d.data,
                    "parent": d.parent.model_dump() if d.parent else None,
                }
                for d in self.discrepancies
            ],
        }


def _parse_node(node_row: Dict[str, Any]) -> Dict[str, Any]:
    """Parse raw GraphStore node row into normalized node dict."""
    pik = node_row.get("pik")
    if pik is None:
        raw_pik = node_row.get("pik_json")
        pik = json.loads(raw_pik) if isinstance(raw_pik, str) else (raw_pik or {})

    data = node_row.get("data")
    if data is None:
        raw_data = node_row.get("data_json")
        data = json.loads(raw_data) if isinstance(raw_data, str) else (raw_data or {})

    return {
        "id": node_row["id"],
        "schema_type": node_row["schema_type"],
        "pik": pik,
        "data": data,
    }


async def export_baseline(
    store: GraphStore,
    session_id: str,
    out_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Export current session entity graph as a deterministic ground-truth baseline."""
    raw_nodes = await store.get_all_nodes(session_id)
    parsed_nodes: List[Dict[str, Any]] = []

    for n in raw_nodes:
        if n.get("schema_type") == "audit.drift":
            continue
        parsed_nodes.append(_parse_node(n))

    # Sort nodes by id for deterministic serialization
    parsed_nodes.sort(key=lambda x: x["id"])

    baseline = {
        "version": "1.0",
        "session_id": session_id,
        "nodes": parsed_nodes,
    }

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    return baseline


def load_baseline(baseline_path_or_dict: Union[str, Path, Dict[str, Any]]) -> Dict[str, Any]:
    """Load baseline dictionary from a file path, JSON string, or dict."""
    if isinstance(baseline_path_or_dict, dict):
        return baseline_path_or_dict

    if isinstance(baseline_path_or_dict, str) and baseline_path_or_dict.lstrip().startswith("{"):
        return json.loads(baseline_path_or_dict)

    p = Path(baseline_path_or_dict)
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


async def audit_drift(
    store: GraphStore,
    session_id: str,
    baseline: Union[str, Path, Dict[str, Any]],
    mode: str = "topology",
    record_findings: bool = False,
) -> DriftReport:
    """Audit observed session entity graph against baseline specification.

    Args:
        store: GraphStore instance.
        session_id: Observed session ID to inspect.
        baseline: Baseline dictionary or file path.
        mode: Audit mode ('topology' or 'strict').
        record_findings: Whether to save generated AuditDrift findings into session graph.
    """
    baseline_data = load_baseline(baseline)
    expected_nodes_list = baseline_data.get("nodes", [])

    raw_observed = await store.get_all_nodes(session_id)
    observed_nodes_list = [
        _parse_node(n) for n in raw_observed if n.get("schema_type") != "audit.drift"
    ]

    expected_by_id = {n["id"]: n for n in expected_nodes_list}
    observed_by_id = {n["id"]: n for n in observed_nodes_list}

    e_ids = set(expected_by_id.keys())
    o_ids = set(observed_by_id.keys())

    intersection = e_ids & o_ids
    union = e_ids | o_ids

    if not union:
        d_topo = 0.0
    else:
        d_topo = 1.0 - (len(intersection) / len(union))

    discrepancies: List[AuditDrift] = []

    # 1. Missing entities (in expected baseline, absent in observed graph)
    for nid in sorted(e_ids - o_ids):
        node = expected_by_id[nid]
        schema = node["schema_type"]
        pik = node["pik"]
        data = node["data"]

        if schema == "network.service":
            host_ip = pik.get("host_ip") or data.get("host_ip", "unknown")
            port = pik.get("port") or data.get("port")
            svc_name = data.get("service_name") or "unknown"
            disc_type = "missing_service"
            target_key = f"{host_ip}:{port}"
            desc = f"Expected service {target_key} ({svc_name}) was not observed."
        elif schema == "network.host":
            host_ip = pik.get("ip") or data.get("ip", "unknown")
            port = None
            disc_type = "missing_host"
            target_key = host_ip
            desc = f"Expected host {target_key} was not observed."
        elif schema == "web.endpoint":
            url = pik.get("url") or data.get("url", "")
            host_ip = None
            port = None
            disc_type = "missing_endpoint"
            target_key = url
            desc = f"Expected web endpoint {url} was not observed."
        else:
            host_ip = pik.get("host_ip") or pik.get("ip")
            port = pik.get("port")
            disc_type = f"missing_{schema.replace('.', '_')}"
            target_key = nid
            desc = f"Expected {schema} finding {nid} was not observed."

        drift_finding = AuditDrift.create(
            discrepancy_type=disc_type,
            target_key=target_key,
            description=desc,
            expected=data,
            observed=None,
            severity="high" if "service" in disc_type or "host" in disc_type else "medium",
            host_ip=host_ip,
            port=int(port) if port is not None else None,
        )
        discrepancies.append(drift_finding)

    # 2. Rogue / unexpected entities (in observed graph, absent in expected baseline)
    for nid in sorted(o_ids - e_ids):
        node = observed_by_id[nid]
        schema = node["schema_type"]
        pik = node["pik"]
        data = node["data"]

        if schema == "network.service":
            host_ip = pik.get("host_ip") or data.get("host_ip", "unknown")
            port = pik.get("port") or data.get("port")
            svc_name = data.get("service_name") or "unknown"
            disc_type = "rogue_service"
            target_key = f"{host_ip}:{port}"
            desc = f"Unexpected rogue service observed on {target_key} ({svc_name})."
        elif schema == "network.host":
            host_ip = pik.get("ip") or data.get("ip", "unknown")
            port = None
            disc_type = "rogue_host"
            target_key = host_ip
            desc = f"Unexpected rogue host observed at {target_key}."
        elif schema == "web.endpoint":
            url = pik.get("url") or data.get("url", "")
            host_ip = None
            port = None
            disc_type = "unexpected_endpoint"
            target_key = url
            desc = f"Unexpected endpoint observed: {url}."
        else:
            host_ip = pik.get("host_ip") or pik.get("ip")
            port = pik.get("port")
            disc_type = f"unexpected_{schema.replace('.', '_')}"
            target_key = nid
            desc = f"Unexpected {schema} finding observed: {nid}."

        drift_finding = AuditDrift.create(
            discrepancy_type=disc_type,
            target_key=target_key,
            description=desc,
            expected=None,
            observed=data,
            severity="high" if "rogue" in disc_type else "medium",
            host_ip=host_ip,
            port=int(port) if port is not None else None,
        )
        discrepancies.append(drift_finding)

    # 3. Strict mode attribute & version comparisons for matching nodes
    strict_discrepancies: List[AuditDrift] = []
    if mode == "strict":
        for nid in sorted(intersection):
            e_node = expected_by_id[nid]
            o_node = observed_by_id[nid]
            e_data = e_node["data"]
            o_data = o_node["data"]
            schema = e_node["schema_type"]
            pik = e_node["pik"]

            host_ip = pik.get("host_ip") or pik.get("ip")
            port = pik.get("port")
            target_key = f"{host_ip}:{port}" if (host_ip and port is not None) else (host_ip or nid)

            # Check service name / version divergence
            e_svc = e_data.get("service_name")
            o_svc = o_data.get("service_name")
            if e_svc and o_svc and e_svc != o_svc:
                strict_discrepancies.append(
                    AuditDrift.create(
                        discrepancy_type="version_divergence",
                        target_key=target_key,
                        description=(
                            f"Service name/version divergence on {target_key}: "
                            f"expected '{e_svc}', observed '{o_svc}'"
                        ),
                        expected=e_svc,
                        observed=o_svc,
                        severity="medium",
                        host_ip=host_ip,
                        port=int(port) if port is not None else None,
                    )
                )

            e_ver = e_data.get("version")
            o_ver = o_data.get("version")
            if e_ver and o_ver and e_ver != o_ver and not (e_svc and o_svc and e_svc != o_svc):
                strict_discrepancies.append(
                    AuditDrift.create(
                        discrepancy_type="version_divergence",
                        target_key=target_key,
                        description=(
                            f"Software version divergence on {target_key}: "
                            f"expected '{e_ver}', observed '{o_ver}'"
                        ),
                        expected=e_ver,
                        observed=o_ver,
                        severity="medium",
                        host_ip=host_ip,
                        port=int(port) if port is not None else None,
                    )
                )

            e_banner = e_data.get("banner")
            o_banner = o_data.get("banner")
            if e_banner and o_banner and e_banner != o_banner:
                strict_discrepancies.append(
                    AuditDrift.create(
                        discrepancy_type="version_divergence",
                        target_key=target_key,
                        description=(
                            f"Banner divergence on {target_key}: "
                            f"expected '{e_banner}', observed '{o_banner}'"
                        ),
                        expected=e_banner,
                        observed=o_banner,
                        severity="low",
                        host_ip=host_ip,
                        port=int(port) if port is not None else None,
                    )
                )

            if schema == "web.endpoint":
                url = pik.get("url") or o_data.get("url") or target_key
                e_raw_headers = e_data.get("headers") or e_data.get("security_headers")
                o_raw_headers = o_data.get("headers") or o_data.get("security_headers")
                e_hdrs = (
                    {str(k).lower(): v for k, v in e_raw_headers.items()}
                    if isinstance(e_raw_headers, dict)
                    else {}
                )
                o_hdrs = (
                    {str(k).lower(): v for k, v in o_raw_headers.items()}
                    if isinstance(o_raw_headers, dict)
                    else {}
                )
                security_header_names = (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                )
                missing_hdrs: List[str] = []
                for hdr in security_header_names:
                    if hdr in e_hdrs and hdr not in o_hdrs:
                        missing_hdrs.append(hdr)
                    elif isinstance(o_raw_headers, dict) and hdr not in o_hdrs:
                        if hdr == "strict-transport-security" and not str(url).startswith(
                            "https://"
                        ):
                            continue
                        if hdr in (
                            "strict-transport-security",
                            "content-security-policy",
                            "x-frame-options",
                            "x-content-type-options",
                        ):
                            missing_hdrs.append(hdr)

                for hdr in missing_hdrs:
                    strict_discrepancies.append(
                        AuditDrift.create(
                            discrepancy_type="missing_security_header",
                            target_key=str(url),
                            description=(
                                f"Missing mandatory HTTP security header '{hdr}' on {url}"
                            ),
                            expected=e_hdrs.get(hdr, "present"),
                            observed=None,
                            severity="medium",
                            host_ip=o_data.get("host_ip") or host_ip,
                            port=int(o_data["port"])
                            if o_data.get("port") is not None
                            else (int(port) if port is not None else None),
                        )
                    )

    if mode == "strict" and strict_discrepancies:
        discrepancies.extend(strict_discrepancies)
        attr_divergence_ratio = len(strict_discrepancies) / max(1, len(intersection))
        final_score = min(1.0, d_topo + (1.0 - d_topo) * 0.5 * attr_divergence_ratio)
        if d_topo == 0.0:
            final_score = min(1.0, 0.5 * attr_divergence_ratio)
    else:
        final_score = d_topo

    final_score = round(final_score, 4)

    if record_findings and discrepancies:
        await store.upsert_findings_batch(session_id, list(discrepancies))

    summary = {
        "expected_count": len(expected_nodes_list),
        "observed_count": len(observed_nodes_list),
        "matching_count": len(intersection),
        "missing_count": len(e_ids - o_ids),
        "unexpected_count": len(o_ids - e_ids),
        "strict_divergence_count": len(strict_discrepancies) if mode == "strict" else 0,
        "topological_distance": round(d_topo, 4),
        "mode": mode,
    }

    return DriftReport(
        session_id=session_id,
        drift_score=final_score,
        mode=mode,
        discrepancies=discrepancies,
        summary=summary,
    )
