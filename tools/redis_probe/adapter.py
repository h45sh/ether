"""Native pure-Python Redis RESP protocol prober tool adapter."""

import asyncio
from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.database import DatabaseService


class RedisProbeAdapter(ToolAdapter):
    """Native in-process coroutine prober for Redis databases."""

    name = "redis_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True  # Pure Python stdlib asyncio

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        return ["redis_probe", host]

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
        host = self.extract_host(target)
        if not host:
            return

        port = 6379
        if target.schema_type == "network.service":
            port = int(target.pik.get("port", 6379))
        elif "port" in params:
            port = int(params["port"])

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
        except Exception as e:
            await context.spool_line(
                f"Failed to connect to Redis on {host}:{port}: {e}", is_error=True
            )
            return

        try:
            # Send INFO\r\n command
            writer.write(b"INFO\r\n")
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(4096), timeout=3.0)
            text = resp.decode("utf-8", errors="replace")

            auth_required = True
            version = "unknown"
            banner = None

            if "NOAUTH" in text:
                auth_required = True
                banner = "Redis requires authentication (NOAUTH)"
            elif "# Server" in text or "redis_version:" in text:
                auth_required = False
                for line in text.splitlines():
                    if line.startswith("redis_version:"):
                        version = line.split(":", 1)[1].strip()
                        break
                banner = f"Unauthenticated Redis {version} instance"

            writer.close()
            await writer.wait_closed()

            yield DatabaseService.create(
                host_ip=host,
                port=port,
                db_type="redis",
                version=version,
                auth_required=auth_required,
                banner=banner or "Redis key-value store",
                ssl_enabled=False,
            )
        except Exception as e:
            await context.spool_line(
                f"Error communicating with Redis on {host}:{port}: {e}", is_error=True
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
