"""Arjun parameter discovery tool adapter."""

import json
import re
from typing import Any, AsyncIterator, Dict, List

from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebParameter

_ARJUN_PARAM_PATTERN = re.compile(
    r"\[\+\]\s+valid parameter found:\s*(\S+)(?:\s+\((\w+)\))?", re.IGNORECASE
)


class ArjunAdapter(ToolAdapter):
    """Adapter for Arjun parameter discovery tool."""

    name = "arjun"

    def validate_install(self) -> bool:
        return self.is_binary_available("arjun")

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        url = self.extract_url(target)
        flag_args = self.normalize_flags(params)

        args = ["arjun"]
        if flag_args:
            args.extend(flag_args)

        if not any(f in args for f in ("-oJ", "-oT")):
            args.extend(["-oJ", "-"])

        if url and "-u" not in args and "--url" not in args:
            args.extend(["-u", url])
        elif not url and not flag_args:
            raise ValueError("Target finding must specify a URL for arjun.")

        return args

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        target_url = self.extract_url(target) or ""
        clean_text = self.strip_ansi(raw_stdout).strip()
        if not clean_text:
            return

        # Attempt JSON parsing: Arjun emits {"url": {"params": ["id", "debug"]}} or {"url": "...", "params": [...]}
        if clean_text.startswith("{") or clean_text.startswith("["):
            try:
                data = json.loads(clean_text)
                if isinstance(data, dict):
                    # Format 1: {url: [params]}
                    for k, v in data.items():
                        if isinstance(v, list):
                            for p in v:
                                yield WebParameter.create(
                                    endpoint_url=k if k.startswith("http") else target_url,
                                    param_name=str(p),
                                    method="GET",
                                )
                        elif isinstance(v, dict):
                            params = v.get("params", [])
                            for p in params:
                                yield WebParameter.create(
                                    endpoint_url=k if k.startswith("http") else target_url,
                                    param_name=str(p),
                                    method=v.get("method", "GET"),
                                )
                return
            except Exception:
                pass

        # Text line parsing
        for line in clean_text.splitlines():
            m = _ARJUN_PARAM_PATTERN.search(line)
            if m:
                param = m.group(1)
                method = m.group(2) or "GET"
                if target_url:
                    yield WebParameter.create(
                        endpoint_url=target_url,
                        param_name=param,
                        method=method,
                    )
