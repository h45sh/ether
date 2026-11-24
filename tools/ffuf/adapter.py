"""FFUF tool adapter."""

import json
import logging
import re
import shlex
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.registry.wordlists import resolve_wordlist, substitute_wordlist_macros
from ether.schemas.base import BaseFinding
from ether.schemas.vulnerability import AuditMisconfig
from ether.schemas.web import WebEndpoint

logger = logging.getLogger(__name__)


async def calibrate_fuzzer_baseline(url: str, timeout_sec: float = 3.0) -> Optional[Dict[str, Any]]:
    """Probe random non-existent path to detect custom 404 / wildcard response geometry.

    Returns dict with 'size', 'words', 'lines', 'status_code' if server responds uniformly,
    or None if fail-open on network timeout / error.
    """
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return None

    nonce = uuid.uuid4().hex[:8]
    probe_url = f"{url.rstrip('/')}/.ether_probe_{nonce}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout_sec, follow_redirects=True) as client:
            resp = await client.get(probe_url)
            text = resp.text
            return {
                "status_code": resp.status_code,
                "size": len(resp.content),
                "words": len(text.split()),
                "lines": len(text.splitlines()),
            }
    except Exception as e:
        logger.warning(f"Fuzzer baseline calibration failed-open on {probe_url}: {e}")
        return None


class FfufAdapter(ToolAdapter):
    """Adapter for the ffuf fast web fuzzer."""

    SENSITIVE_PATTERN = re.compile(
        r"(?:\.(?:env|git|bak|old|config|conf|json|yml|yaml|sql|db|sqlite|tar|gz|zip)|\b(?:admin|backup|secrets?|credentials?))\b",
        re.IGNORECASE,
    )
    LINE_PATTERN = re.compile(
        r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)",
        re.MULTILINE,
    )

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Execute ffuf scan with pre-flight response geometry baseline calibration."""
        url = self.extract_url(target)
        if url and not params.get("skip_calibration"):
            calib = await calibrate_fuzzer_baseline(url)
            if calib and calib.get("size") is not None:
                params = dict(params)
                raw_flags = params.get("raw_flags", "")
                if "-fs" not in raw_flags:
                    params["raw_flags"] = f"{raw_flags} -fs {calib['size']}".strip()

        async for finding in super().execute_action(target, params, context):
            yield finding

    def validate_install(self) -> bool:
        """Check if ffuf binary is available in PATH."""
        return self.is_binary_available("ffuf")

    def sanitize_output(self, raw_stdout: str) -> str:
        """Strip ffuf ASCII art, progress lines, and metadata blocks."""
        lines = []
        for line in raw_stdout.splitlines():
            s = line.strip()
            if s.startswith("::") or "Progress: [" in s or s.startswith("____"):
                continue
            lines.append(line)
        return "\n".join(lines)

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct the ffuf command line execution."""
        # 1. Resolve target URL
        url = self.extract_url(target)

        # 2. Process flags and substitute macros
        raw_flags = params.get("raw_flags", "").strip()
        raw_flags, _ = substitute_wordlist_macros(raw_flags)
        flag_args = shlex.split(raw_flags) if raw_flags else []

        args = ["ffuf"]

        # Ensure -u flag is present
        has_u = any(flag_args[i] == "-u" for i in range(len(flag_args)))
        if not has_u:
            if not url:
                raise ValueError(
                    f"Target finding {target.schema_type} has no URL or host identifier, and no -u flag provided."
                )
            base_url = url.rstrip("/")
            # If FUZZ keyword is not in URL, append /FUZZ
            fuzz_url = base_url if "FUZZ" in base_url else f"{base_url}/FUZZ"
            args.extend(["-u", fuzz_url])

        # Ensure -w wordlist flag is present
        has_w = any(flag_args[i] == "-w" for i in range(len(flag_args)))
        if not has_w:
            default_wl = resolve_wordlist("common_dirs")
            args.extend(["-w", str(default_wl)])

        # Ensure JSON output is captured
        has_of = any(flag_args[i] == "-of" for i in range(len(flag_args)))
        if not has_of:
            args.extend(["-of", "json", "-o", "-"])

        # Add user-provided flags (ignoring duplicates of handled flags)
        args.extend(flag_args)
        return args

    def _extract_url(self, target: BaseFinding) -> Optional[str]:
        return self.extract_url(target)

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Dict[str, Any] = None
    ) -> AsyncIterator[BaseFinding]:
        """Parse structured JSON results or stdout lines from ffuf."""
        cleaned = raw_stdout.strip()
        if not cleaned:
            return

        host_ip = target.pik.get("host_ip") or target.pik.get("ip") or target.data.get("host_ip")

        # 1. Try parsing JSON payload
        json_obj = self._parse_json(cleaned)
        if json_obj and "results" in json_obj:
            results = json_obj.get("results", [])
            for item in results:
                if not isinstance(item, dict):
                    continue

                endpoint_url = item.get("url", "").strip()
                if not endpoint_url:
                    continue

                status_code = int(item.get("status", 200))
                length = int(item.get("length", 0))
                words = int(item.get("words", 0))
                lines = int(item.get("lines", 0))
                fuzz_word = str(item.get("input", {}).get("FUZZ", ""))

                # Yield endpoint finding
                yield WebEndpoint.create(
                    url=endpoint_url,
                    host_ip=host_ip,
                    status_code=status_code,
                    content_length=length,
                    words=words,
                    lines=lines,
                )

                # Check for sensitive misconfiguration exposure
                if status_code in (200, 301, 302, 307) and self.SENSITIVE_PATTERN.search(fuzz_word):
                    yield AuditMisconfig.create(
                        target=endpoint_url,
                        check_id="exposed-sensitive-file",
                        title=f"Exposed Sensitive Resource ({fuzz_word})",
                        severity="high" if status_code == 200 else "medium",
                        host_ip=host_ip,
                        remediation="Restrict access to sensitive configuration, backup, or administrative paths.",
                    )
            return

        # 2. Fallback: Parse line-by-line CLI output
        base_url = self.extract_url(target) or ""
        for match in self.LINE_PATTERN.finditer(cleaned):
            word, status_str, size_str, words_str, lines_str = match.groups()
            endpoint_url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
            status_code = int(status_str)

            yield WebEndpoint.create(
                url=endpoint_url,
                host_ip=host_ip,
                status_code=status_code,
                content_length=int(size_str),
                words=int(words_str),
                lines=int(lines_str),
            )

            if status_code in (200, 301, 302, 307) and self.SENSITIVE_PATTERN.search(word):
                yield AuditMisconfig.create(
                    target=endpoint_url,
                    check_id="exposed-sensitive-file",
                    title=f"Exposed Sensitive Resource ({word})",
                    severity="high" if status_code == 200 else "medium",
                    host_ip=host_ip,
                )

    def _parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    return None
            return None

    def sanitize_output(self, raw_stdout: str) -> str:
        """Strip ASCII banner and noisy progress lines from ffuf output."""
        lines = []
        for line in raw_stdout.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("::") or s.startswith("Progress: [") or "Progress: [" in s:
                continue
            if any(banner_fragment in line for banner_fragment in ("/'___\\", "'___/ \\ \\ \\__/")):
                continue
            lines.append(line)
        return "\n".join(lines)
