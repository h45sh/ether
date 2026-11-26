"""Cloud Enum multi-cloud OSINT tool adapter."""

import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.cloud import CloudAsset

_OPEN_BUCKET_PATTERN = re.compile(
    r"\[\+\]\s+OPEN\s+(AWS|AZURE|GCP)\s+([A-Z0-9_\s]+)?:\s*(\S+)",
    re.IGNORECASE,
)


class CloudEnumAdapter(ToolAdapter):
    """Adapter for cloud_enum multi-cloud asset discovery tool."""

    name = "cloud_enum"

    def validate_install(self) -> bool:
        return self.is_binary_available("cloud_enum") or self.is_binary_available("cloud_enum.py")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        keyword = target.pik.get("domain") or target.data.get("domain") or "target"
        if "." in keyword:
            keyword = keyword.split(".")[0]

        flag_args = self.normalize_flags(params)

        binary = "cloud_enum" if self.is_binary_available("cloud_enum") else "cloud_enum.py"
        args = [binary, "-k", keyword, "-l", "-"]
        if flag_args:
            args.extend(flag_args)

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        for line in raw_stdout.splitlines():
            clean = self.strip_ansi(line).strip()
            if not clean:
                continue

            # [+] OPEN AWS Bucket: target-backups.s3.amazonaws.com
            m = _OPEN_BUCKET_PATTERN.search(clean)
            if m:
                provider = m.group(1).lower()
                resource_url = m.group(3)
                resource_id = (
                    resource_url.split(".")[0].replace("http://", "").replace("https://", "")
                )
                yield CloudAsset.create(
                    provider=provider,
                    resource_id=resource_id,
                    service="storage",
                    public_access=True,
                    url=resource_url,
                )
