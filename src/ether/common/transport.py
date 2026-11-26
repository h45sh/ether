"""DNS-pinned HTTP socket transport and redirect SSRF defense (ether.common.transport)."""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
import typing
import urllib.parse
from typing import Any, Optional

import httpcore
import httpx

from ether.common.scope import EngagementScope, ScopeValidator


class SSRFPinnedError(httpx.TransportError):
    """Raised when DNS resolution, IP pinning, or redirect validation violates EngagementScope."""


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Custom httpcore network backend that pins TCP connections to pre-validated IPs."""

    def __init__(
        self,
        scope: EngagementScope,
        policy_is_unrestricted: bool = False,
        inner: Optional[httpcore.AsyncNetworkBackend] = None,
    ) -> None:
        self._scope = scope
        self._policy_is_unrestricted = policy_is_unrestricted
        self._inner = inner or httpcore.AsyncNetworkBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,  # noqa: ASYNC109
        local_address: Optional[str] = None,
        socket_options: Optional[typing.Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        verdict = await ScopeValidator.check_destination(
            host,
            scope=self._scope,
            policy_is_unrestricted=self._policy_is_unrestricted,
        )
        if not verdict.allowed:
            raise SSRFPinnedError(f"Pinned transport blocked '{host}': {verdict.reason}")

        pinned_ip = host
        if ScopeValidator.parse_ip(host) is None:
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=1.0)
                resolved = list(dict.fromkeys(str(info[4][0]) for info in infos if info[4]))
            except Exception:
                resolved = []
            if not resolved:
                if not self._policy_is_unrestricted:
                    raise SSRFPinnedError(f"Pinned transport could not resolve '{host}'.")
            else:
                for ip_str in resolved:
                    ip_verdict = ScopeValidator.is_in_scope(
                        ip_str,
                        scope=self._scope,
                        policy_is_unrestricted=self._policy_is_unrestricted,
                    )
                    if not ip_verdict.allowed:
                        raise SSRFPinnedError(
                            f"Pinned transport blocked resolved IP '{ip_str}' for '{host}': {ip_verdict.reason}"
                        )
                v4 = [
                    ip
                    for ip in resolved
                    if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
                ]
                pinned_ip = v4[0] if v4 else resolved[0]

        return await self._inner.connect_tcp(
            host=pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,  # noqa: ASYNC109
        socket_options: Optional[typing.Iterable[Any]] = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_unix_socket(
            path=path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


_ORIG_ASYNC_HTTP_TRANSPORT = httpx.AsyncHTTPTransport


class _CoreAsyncStream(httpx.AsyncByteStream):
    """Wrap an httpcore response stream as an httpx.AsyncByteStream."""

    def __init__(self, stream: typing.AsyncIterable[bytes]) -> None:
        self._stream = stream

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        aclose_fn = getattr(self._stream, "aclose", None)
        if callable(aclose_fn):
            await aclose_fn()


class _PinnedPoolTransport(httpx.AsyncBaseTransport):
    """Clean AsyncBaseTransport wrapping a DNS-pinned httpcore.AsyncConnectionPool."""

    def __init__(self, pool: httpcore.AsyncConnectionPool) -> None:
        self._pool = pool

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        resp = await self._pool.handle_async_request(req)
        stream = typing.cast(typing.AsyncIterable[bytes], resp.stream)
        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_CoreAsyncStream(stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class PinnedTransport:
    """Factory for DNS-pinned, redirect-guarded httpx.AsyncClient instances."""

    @staticmethod
    def create_client(
        scope: Optional[EngagementScope] = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
        policy_is_unrestricted: bool = False,
        max_redirects: int = 5,
    ) -> httpx.AsyncClient:
        """Create an httpx.AsyncClient that pins DNS to validated IPs and guards redirects."""
        effective_scope = scope or EngagementScope()
        ssl_context = ssl.create_default_context() if verify_tls else False

        backend = _PinnedNetworkBackend(
            scope=effective_scope,
            policy_is_unrestricted=policy_is_unrestricted,
        )
        pool = httpcore.AsyncConnectionPool(
            network_backend=backend,
            ssl_context=ssl_context if isinstance(ssl_context, ssl.SSLContext) else None,
        )
        transport: httpx.AsyncBaseTransport
        if isinstance(httpx.AsyncHTTPTransport, type) and getattr(
            httpx.AsyncHTTPTransport, "__module__", ""
        ).startswith("httpx"):
            transport = _PinnedPoolTransport(pool)
        else:
            transport = httpx.AsyncHTTPTransport(verify=verify_tls)

        async def _redirect_guard(response: httpx.Response) -> None:
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                if not location:
                    return
                resolved_url = urllib.parse.urljoin(str(response.url), location)
                verdict = await ScopeValidator.check_destination(
                    resolved_url,
                    scope=effective_scope,
                    policy_is_unrestricted=policy_is_unrestricted,
                )
                if not verdict.allowed:
                    raise SSRFPinnedError(
                        f"Redirect to '{resolved_url}' blocked by EngagementScope: {verdict.reason}"
                    )

        return httpx.AsyncClient(
            transport=transport,
            verify=verify_tls,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects,
            event_hooks={"response": [_redirect_guard]},
        )
