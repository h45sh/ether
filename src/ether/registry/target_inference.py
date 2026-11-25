"""Pure target-string inference into typed BaseFinding entities."""

import ipaddress

from ether.schemas.base import BaseFinding
from ether.schemas.dns import DomainInfo
from ether.schemas.network import NetworkHost
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

    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return BaseFinding(
                schema_type="network.netblock", pik={"cidr": target}, data={"cidr": target}
            )
        except ValueError:
            pass

    return DomainInfo.create(domain=target)
