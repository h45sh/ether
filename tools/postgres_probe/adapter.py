"""Native pure-Python PostgreSQL protocol prober tool adapter."""

import asyncio
from typing import Any, AsyncIterator, Dict, List

from ether.common.context import ExecutionContext
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.database import DatabaseService


class PostgresProbeAdapter(ToolAdapter):
    """Native in-process coroutine prober for PostgreSQL services."""

    name = "postgres_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        return True  # Pure Python stdlib asyncio

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        host = self.extract_host(target) or "127.0.0.1"
        return ["postgres_probe", host]

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

        port = 5432
        if target.schema_type == "network.service":
            port = int(target.pik.get("port", 5432))
        elif "port" in params:
            port = int(params["port"])

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
        except Exception as e:
            await context.spool_line(
                f"Failed to connect to PostgreSQL on {host}:{port}: {e}", is_error=True
            )
            return

        try:
            # 1. Send SSLRequest (Length: 8 bytes, Code: 80877103 -> 0x04D2162F)
            writer.write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
            await writer.drain()

            ssl_resp = await asyncio.wait_for(reader.read(1), timeout=3.0)
            ssl_enabled = ssl_resp == b"S"

            # 2. Send StartupMessage with user=postgres (Length: 4 bytes, Proto 3.0: 196608 -> 0x00030000)
            user_payload = b"user\x00postgres\x00database\x00postgres\x00\x00"
            pkt_len = 4 + 4 + len(user_payload)
            startup_pkt = pkt_len.to_bytes(4, byteorder="big") + b"\x00\x03\x00\x00" + user_payload
            writer.write(startup_pkt)
            await writer.drain()

            resp = await asyncio.wait_for(reader.read(256), timeout=3.0)
            auth_required = True
            banner = None
            if resp:
                pkt_type = chr(resp[0])
                if pkt_type == "R":
                    auth_type = int.from_bytes(resp[5:9], byteorder="big") if len(resp) >= 9 else -1
                    auth_required = auth_type != 0
                    banner = f"PostgreSQL AuthType {auth_type}"
                elif pkt_type == "E":
                    banner = "PostgreSQL ErrorResponse"

            writer.close()
            await writer.wait_closed()

            yield DatabaseService.create(
                host_ip=host,
                port=port,
                db_type="postgresql",
                version="unknown",
                auth_required=auth_required,
                banner=banner or "PostgreSQL server",
                ssl_enabled=ssl_enabled,
            )
        except Exception as e:
            await context.spool_line(
                f"Error communicating with PostgreSQL on {host}:{port}: {e}", is_error=True
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
