"""Native pure-Python MySQL protocol prober tool adapter."""

import asyncio
from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.database import DatabaseService


class MysqlProbeAdapter(ToolAdapter):
    """Native in-process coroutine prober for MySQL services."""

    name = "mysql_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True  # Pure Python stdlib asyncio

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        return ["mysql_probe", host]

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

        port = 3306
        if target.schema_type == "network.service":
            port = int(target.pik.get("port", 3306))
        elif "port" in params:
            port = int(params["port"])

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
        except Exception as e:
            await context.spool_line(
                f"Failed to connect to MySQL on {host}:{port}: {e}", is_error=True
            )
            return

        try:
            # Read initial handshake packet
            # MySQL packet header: 3 bytes payload length, 1 byte sequence ID
            header = await asyncio.wait_for(reader.readexactly(4), timeout=3.0)
            payload_len = header[0] | (header[1] << 8) | (header[2] << 16)
            payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=3.0)

            # Protocol version (1 byte, typically 10 for MySQL 5.x/8.x)
            proto_version = payload[0]
            # Server version (null-terminated string)
            null_pos = payload.find(b"\x00", 1)
            server_version = (
                payload[1:null_pos].decode("latin1", errors="replace")
                if null_pos != -1
                else "unknown"
            )

            # Parse capabilities
            ssl_enabled = False
            if len(payload) > null_pos + 15:
                caps_low = payload[null_pos + 5] | (payload[null_pos + 6] << 8)
                ssl_enabled = bool(caps_low & 0x0800)  # CLIENT_SSL

            writer.close()
            await writer.wait_closed()

            yield DatabaseService.create(
                host_ip=host,
                port=port,
                db_type="mysql",
                version=server_version,
                auth_required=True,
                banner=f"MySQL proto {proto_version}, version {server_version}",
                ssl_enabled=ssl_enabled,
            )
        except Exception as e:
            await context.spool_line(
                f"Error parsing MySQL handshake from {host}:{port}: {e}", is_error=True
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
