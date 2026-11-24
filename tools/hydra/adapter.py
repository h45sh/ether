"""THC Hydra network logon cracker tool adapter."""

import re
import shlex
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.credential import CredentialFound

_HYDRA_PATTERN = re.compile(
    r"\[\d+\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login(?::|\s)\s*(\S+)\s+password(?::|\s)\s*(\S+)",
    re.IGNORECASE,
)


class HydraAdapter(ToolAdapter):
    """Adapter for THC Hydra network credential auditing suite."""

    name = "hydra"

    def validate_install(self) -> bool:
        return self.is_binary_available("hydra")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        service = "ssh"
        if target.schema_type == "network.service":
            service = target.data.get("service_name") or "ssh"

        raw_flags = params.get("raw_flags", "")

        args = ["hydra", "-V"]
        if raw_flags:
            args.extend(shlex.split(raw_flags))

        if host and host not in args:
            args.extend([host, service])

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # [22][ssh] host: 192.168.1.100   login: root   password: toor
            m = _HYDRA_PATTERN.search(clean)
            if m:
                proto, host, username, password = m.group(1), m.group(2), m.group(3), m.group(4)
                yield CredentialFound.create(
                    context=f"{host}:{proto}",
                    username=username,
                    password=password,
                    host_ip=host,
                )
