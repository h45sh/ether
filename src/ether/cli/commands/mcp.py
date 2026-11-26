"""Handler for 'ether mcp' command."""

import asyncio
import logging
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error
from ether.gateway.gate import GatePolicy
from ether.mcp.server import create_mcp_server

logger = logging.getLogger(__name__)


async def handle_mcp(args: Any, context: CliContext) -> int:
    """Launch the Native Model Context Protocol (MCP) server."""
    mcp_cfg = context.settings.mcp
    transport = getattr(args, "transport", None) or mcp_cfg.transport
    session_id = getattr(args, "session_id", None)
    port = int(getattr(args, "port", None) or mcp_cfg.port)
    host = getattr(args, "host", None) or mcp_cfg.host
    policy_str = getattr(
        args, "policy", context.policy.value if hasattr(context, "policy") else "safe"
    )
    policy = GatePolicy.UNRESTRICTED if policy_str == "unrestricted" else GatePolicy.SAFE

    # Read auth token from args or resolved EtherSettings (which already checks ETHER_MCP_AUTH_TOKEN)
    auth_token = getattr(args, "auth_token", None) or mcp_cfg.auth_token

    # Host binding security gate: under SAFE policy with SSE transport, binding to external
    # non-loopback interfaces (e.g. 0.0.0.0 or public IP) requires an authentication token.
    is_loopback = host in ("127.0.0.1", "localhost", "::1", "127.0.0.2")
    if transport == "sse" and not is_loopback and not auth_token:
        if policy == GatePolicy.SAFE:
            print_error(
                f"Binding MCP SSE server to external interface '{host}' under SAFE policy "
                "requires authentication. Provide --auth-token <TOKEN> or set ETHER_MCP_AUTH_TOKEN."
            )
            return EXIT_RUNTIME_ERROR
        else:
            logger.warning(
                "Binding MCP SSE server to external interface '%s' without authentication under UNRESTRICTED policy.",
                host,
            )

    security_middleware = None
    if transport == "sse" and auth_token:
        from ether.mcp.security import LeakyBucketRateLimiter, SecurityMiddleware

        security_middleware = SecurityMiddleware(
            signing_secret=auth_token,
            previous_secrets=mcp_cfg.previous_secrets,
            allowed_origins=mcp_cfg.allowed_origins,
            trusted_mtls_fingerprints=mcp_cfg.trusted_mtls_fingerprints,
            require_mtls=mcp_cfg.require_mtls,
            rate_limiter=LeakyBucketRateLimiter(
                capacity=mcp_cfg.rate_limit_capacity,
                refill_per_sec=mcp_cfg.rate_limit_refill_per_sec,
            ),
            static_admin_token=auth_token if mcp_cfg.allow_static_admin else None,
            allow_static_admin=mcp_cfg.allow_static_admin,
            static_admin_scopes=mcp_cfg.static_admin_scopes,
        )

    registry = context.get_registry()
    async with context.open_store() as store:
        server = create_mcp_server(
            store=store,
            default_session_id=session_id,
            policy=policy,
            registry=registry,
            auth_token=auth_token,
            settings=context.settings,
            security_middleware=security_middleware,
        )

        try:
            if transport == "stdio":
                await server.run_stdio_async()
            elif transport == "sse":
                await server.run_sse_async(host=host, port=port)
            else:
                print_error(f"Unsupported transport '{transport}'. Use 'stdio' or 'sse'.")
                return EXIT_RUNTIME_ERROR
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        except Exception as e:
            print_error(f"MCP server runtime error: {e}")
            return EXIT_RUNTIME_ERROR

    return EXIT_SUCCESS
