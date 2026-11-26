"""Native pure-Python TCP socket prober and banner grabber adapter."""

import asyncio
import time
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.common.exceptions import PolicyViolationError
from ether.common.scope import ScopeValidator
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkHost, NetworkService


class TcpProbeAdapter(ToolAdapter):
    """Pure-Python asynchronous TCP prober extracting service banners and detecting delay tarpits."""

    name = "tcp_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or params.get("port") or 80
        return ["tcp_probe", f"{host}:{port}"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        return
        yield

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or int(params.get("port", 80))

        policy_str = str(getattr(context, "policy", "safe")).lower()
        is_unrestricted = "unrestricted" in policy_str
        verdict = await ScopeValidator.check_destination(
            host, policy_is_unrestricted=is_unrestricted
        )
        if not verdict.allowed:
            raise PolicyViolationError(
                f"Target '{host}' blocked by SSRF policy ({verdict.reason})."
            )

        timeout = float(params.get("timeout", 16.0))
        start_time = time.monotonic()
        banner: Optional[str] = None
        is_tarpit = False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            connect_duration = time.monotonic() - start_time
            if connect_duration >= 15.0:
                is_tarpit = True

            # Attempt non-blocking banner read
            try:
                # Some services greet immediately (SSH, FTP, SMTP); for others, send newline
                if port == 80 or port == 8080:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()

                banner_data = await asyncio.wait_for(reader.read(1024), timeout=min(2.0, timeout))
                if banner_data:
                    banner = banner_data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        except asyncio.TimeoutError:
            connect_duration = time.monotonic() - start_time
            if connect_duration >= 15.0:
                is_tarpit = True
            await context.spool_line(f"TCP probe timed out connecting to {host}:{port}", is_error=True)
            return
        except Exception as e:
            await context.spool_line(f"TCP probe connection failed to {host}:{port}: {e}", is_error=True)
            return

        yield NetworkHost.create(ip=host)

        svc_name = "ssh" if port == 22 else ("http" if port in (80, 8080) else "unknown")
        yield NetworkService.create(
            host_ip=host,
            port=port,
            protocol="tcp",
            service_name=svc_name,
            banner=banner,
            is_tarpit=is_tarpit,
        )
