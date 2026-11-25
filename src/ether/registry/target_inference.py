"""Pure target-string inference into typed BaseFinding entities."""

import ipaddress

from ether.schemas.base import BaseFinding
from ether.schemas.dns import DomainInfo
from ether.schemas.network import NetworkHost, NetworkService
from ether.schemas.web import WebEndpoint


def infer_target_finding(target: str) -> BaseFinding:
    """Infer the typed BaseFinding entity from a raw target string."""
    try:
        ipaddress.ip_address(target)
        return NetworkHost.create(ip=target)
    except ValueError:
        pass

    if target.startswith("http://") or target.startswith("https://"):
        return WebEndpoint.create(url=target)

    # Check for IP:PORT or host:port (network.service)
    if ":" in target and not target.startswith("http://") and not target.startswith("https://"):
        if not target.startswith("[") and target.count(":") == 1:
            host_part, port_part = target.split(":")
            if port_part.isdigit():
                return NetworkService.create(
                    host_ip=host_part,
                    port=int(port_part),
                    protocol="tcp",
                    service_name="unknown",
                )
        elif target.startswith("[") and "]:" in target:
            host_part = target[1 : target.index("]:")]
            port_part = target[target.index("]:") + 2 :]
            if port_part.isdigit():
                return NetworkService.create(
                    host_ip=host_part,
                    port=int(port_part),
                    protocol="tcp",
                    service_name="unknown",
                )

    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return BaseFinding(
                schema_type="network.netblock", pik={"cidr": target}, data={"cidr": target}
            )
        except ValueError:
            pass

    return DomainInfo.create(domain=target)
