"""Native pure-Python Cloud Instance Metadata Service (IMDS) prober."""

from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.common.scope import ScopeValidator
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
        target_url = None
        if target:
            target_url = target.pik.get("url") or target.data.get("url")
        if not target_url:
            target_url = params.get("url") or params.get("target")

        # Under SAFE policy, validate target via ScopeValidator and block direct metadata probing BEFORE any network I/O
        policy_str = str(getattr(context, "policy", "safe")).lower()
        is_safe = policy_str in ("safe", "gatepolicy.safe")
        if is_safe:
            if not target_url or "169.254." in str(target_url):
                raise PolicyViolationError(
                    "Access to cloud metadata IP 169.254.169.254 is forbidden under GatePolicy.SAFE (SSRF defense)."
                )
            verdict = await ScopeValidator.check_destination(
                str(target_url), policy_is_unrestricted=False
            )
            if not verdict.allowed:
                raise PolicyViolationError(
                    f"Target '{target_url}' blocked under GatePolicy.SAFE ({verdict.reason})."
                )

        from ether.common.transport import PinnedTransport

        verify_tls = bool(params.get("verify_tls", True))
        async with PinnedTransport.create_client(
            scope=getattr(context, "scope", None),
            verify_tls=verify_tls,
            timeout=3.0,
            policy_is_unrestricted=not is_safe,
            max_redirects=0,
        ) as client:
            if target_url and target_url.startswith(("http://", "https://")):
                try:
                    resp = await client.get(target_url, follow_redirects=False)
                    if resp.is_redirect:
                        loc = resp.headers.get("Location", "")
                        if "169.254.169.254" in loc or "metadata" in loc:
                            yield CloudAsset.create(
                                provider="redirect",
                                resource_id="open-redirect-to-imds",
                                service="metadata",
                                public_access=True,
                                url=target_url,
                            )
                except Exception:
                    pass

        if is_safe:
            return

        provider = str(params.get("provider", "aws")).lower()

        from ether.common.transport import PinnedTransport

        verify_tls = bool(params.get("verify_tls", True))
        async with PinnedTransport.create_client(
            scope=getattr(context, "scope", None),
            verify_tls=verify_tls,
            timeout=3.0,
            policy_is_unrestricted=not is_safe,
            max_redirects=0,
        ) as client:
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
