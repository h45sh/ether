"""Native pure-Python Cloud Instance Metadata Service (IMDS) prober."""

from typing import Any, AsyncIterator, Dict, List

import httpx

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.cloud import CloudAsset


class ImdsProbeAdapter(ToolAdapter):
    """Native in-process coroutine prober for Cloud Instance Metadata Services."""

    name = "imds_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        return ["imds_probe", "169.254.169.254"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        return
        yield

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        # Under SAFE policy, cloud metadata addresses are strictly blocked
        if str(context.policy).lower() in ("safe", "gatepolicy.safe"):
            raise PolicyViolationError(
                "Access to cloud metadata IP 169.254.169.254 is forbidden under GatePolicy.SAFE (SSRF defense)."
            )

        provider = str(params.get("provider", "aws")).lower()

        async with httpx.AsyncClient(timeout=3.0) as client:
            if provider == "aws":
                # 1. Probe IMDSv2 (Token request)
                try:
                    resp = await client.put(
                        "http://169.254.169.254/latest/api/token",
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    )
                    if resp.status_code == 200:
                        yield CloudAsset.create(
                            provider="aws",
                            resource_id="imds-v2",
                            service="metadata",
                            public_access=False,
                            url="http://169.254.169.254/latest/api/token",
                        )
                except Exception:
                    pass

                # 2. Probe IMDSv1
                try:
                    resp = await client.get("http://169.254.169.254/latest/meta-data/")
                    if resp.status_code == 200:
                        yield CloudAsset.create(
                            provider="aws",
                            resource_id="imds-v1-unprotected",
                            service="metadata",
                            public_access=True,
                            url="http://169.254.169.254/latest/meta-data/",
                        )
                except Exception:
                    pass
