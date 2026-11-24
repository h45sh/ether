"""Native zero-fork in-process TLS prober adapter."""

import asyncio
import hashlib
import ssl
from typing import Any, AsyncIterator, Dict, List, Optional

from ether.common.context import ExecutionContext
from ether.common.ssrf import check_ssrf_safety
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import TLSCertificate, TLSCipherSuite


class TlsProbeAdapter(ToolAdapter):
    """Pure-Python asynchronous TLS prober extracting X.509 certificates and negotiated cipher suites."""

    name = "tls_probe"
    execution_tier = "coroutine"

    def validate_install(self) -> bool:
        """Pure-Python adapter with zero binary dependencies."""
        return True

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """CLI shim if ever invoked via subprocess."""
        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or 443
        return ["tls_probe", f"{host}:{port}"]

    async def parse_output(
        self, raw_stdout: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Fuzz resilience shim."""
        return
        yield

    async def execute_action(
        self,
        target: BaseFinding,
        params: Dict[str, Any],
        context: ExecutionContext,
    ) -> AsyncIterator[BaseFinding]:
        """Perform zero-fork TLS handshake against target and yield certificate and cipher findings."""
        host = self.extract_host(target) or "127.0.0.1"
        port = self.extract_port(target) or 443

        if str(getattr(context, "policy", "safe")).lower() in ("safe", "gatepolicy.safe"):
            check_ssrf_safety(host)

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx),
                timeout=params.get("timeout", 5.0),
            )
        except Exception as e:
            await context.spool_line(f"TLS probe connection failed to {host}:{port}: {e}", is_error=True)
            return

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cipher_info = writer.get_extra_info("cipher")

            der_cert = None
            if ssl_obj:
                try:
                    der_cert = ssl_obj.getpeercert(binary_form=True)
                except Exception:
                    pass

            if der_cert:
                sha256_fp = hashlib.sha256(der_cert).hexdigest()
                yield TLSCertificate.create(
                    fingerprint=sha256_fp,
                    host_ip=host,
                    port=port,
                )

            if cipher_info:
                name, proto, bits = cipher_info
                deprecated = proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3")
                yield TLSCipherSuite.create(
                    host_ip=host,
                    port=port,
                    cipher_suite=name,
                    protocol_version=proto,
                    deprecated=deprecated,
                    bits=bits,
                )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
