"""Native pure-Python Certificate Transparency prober tool adapter."""

from typing import Any, AsyncIterator, Dict, List

import httpx

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.dns import DomainInfo


class CrtshAdapter(ToolAdapter):
    """Native in-process coroutine prober for Certificate Transparency logs via crt.sh."""

    name = "crtsh"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        domain = target.pik.get("domain") or target.data.get("domain") or "example.com"
        return ["crtsh", domain]

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
        domain = target.pik.get("domain") or target.data.get("domain")
        if not domain:
            return

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    await context.spool_line(
                        f"crt.sh returned HTTP {resp.status_code}", is_error=True
                    )
                    return

                data = resp.json()
                seen_names = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        # Strip wildcards (*.example.com -> example.com)
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub and sub not in seen_names:
                            seen_names.add(sub)
                            yield DomainInfo.create(domain=sub)
        except Exception as e:
            await context.spool_line(
                f"Error querying crt.sh for domain {domain}: {e}", is_error=True
            )
