"""Unit tests for RawNetworkGovernor ambient raw socket and unprivileged connect sweeps."""

import pytest

from ether.core.raw_net import RawNetworkGovernor, ServiceProbeResult


@pytest.mark.fast
def test_raw_network_governor_capability():
    cap = RawNetworkGovernor.has_raw_capability()
    assert isinstance(cap, bool)


@pytest.mark.fast
@pytest.mark.asyncio
async def test_raw_network_governor_unprivileged_sweep():
    # Force unprivileged fallback to test non-blocking asyncio sweep hermetically
    results = []
    async for probe in RawNetworkGovernor.fast_syn_sweep(
        target="127.0.0.1",
        ports=[65534, 65535],
        timeout_sec=0.1,
        force_unprivileged=True,
    ):
        results.append(probe)
        assert isinstance(probe, ServiceProbeResult)
    # Closed ports yield 0 open results without errors
    assert len(results) == 0
