"""Gateway re-export of the unified ScopeValidator and EngagementScope seam."""

from ether.common.scope import (
    METADATA_HOSTNAMES,
    METADATA_IPS,
    EngagementScope,
    ScopeValidator,
    ScopeVerdict,
)

__all__ = [
    "EngagementScope",
    "METADATA_HOSTNAMES",
    "METADATA_IPS",
    "ScopeValidator",
    "ScopeVerdict",
]
