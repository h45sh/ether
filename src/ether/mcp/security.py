"""Enterprise MCP transport security middleware (HMAC scoped tokens, rate limit, CORS, mTLS)."""

from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, FrozenSet, Iterable, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


class OperationType(str, Enum):
    """Scoped RBAC permission categories for MCP tool/resource operations."""

    TELEMETRY_READ = "telemetry:read"
    GRAPH_QUERY = "graph:query"
    TOOL_EXECUTE = "tool:execute"
    SESSION_MUTATE = "session:mutate"


ALL_SCOPES: FrozenSet[str] = frozenset(op.value for op in OperationType)
_CURRENT_AUTH_CONTEXT: contextvars.ContextVar[Optional["AuthContext"]] = contextvars.ContextVar(
    "ether_mcp_auth_context", default=None
)


def get_current_auth_context() -> Optional["AuthContext"]:
    """Return the active AuthContext for the current async task, if any."""
    return _CURRENT_AUTH_CONTEXT.get()


def require_operation(operation: OperationType) -> None:
    """Enforce per-tool RBAC when an authenticated AuthContext is active."""
    ctx = _CURRENT_AUTH_CONTEXT.get()
    if ctx is not None and not ctx.has_scope(operation):
        raise AuthError(
            f"Token subject '{ctx.subject}' lacks required scope '{operation.value}'.",
            status_code=403,
        )


@dataclass(frozen=True)
class AuthContext:
    """Verified caller identity and granted permission scopes."""

    subject: str
    scopes: FrozenSet[str]
    transport: str = "http"
    client_ip: str = "127.0.0.1"
    mtls_fingerprint: Optional[str] = None

    def has_scope(self, operation: OperationType) -> bool:
        return operation.value in self.scopes or "*" in self.scopes


class AuthError(PermissionError):
    """Base authentication/authorization failure with HTTP status code."""

    def __init__(self, message: str, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class LeakyBucketRateLimiter:
    """Per-IP sliding-window / leaky-bucket brute-force defense."""

    def __init__(self, capacity: int = 60, refill_per_sec: float = 2.0) -> None:
        self.capacity = float(capacity)
        self.refill_per_sec = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = defaultdict(
            lambda: (self.capacity, time.monotonic())
        )

    def allow(self, client_ip: str) -> bool:
        now = time.monotonic()
        tokens, last_ts = self._buckets[client_ip]
        tokens = min(self.capacity, tokens + (now - last_ts) * self.refill_per_sec)
        if tokens < 1.0:
            self._buckets[client_ip] = (tokens, now)
            return False
        self._buckets[client_ip] = (tokens - 1.0, now)
        return True


class SecurityMiddleware:
    """Unified MCP transport authentication, RBAC scoping, CORS, rate-limiting, and mTLS."""

    def __init__(
        self,
        signing_secret: str | bytes,
        previous_secrets: Sequence[str | bytes] = (),
        allowed_origins: Sequence[str] = (),
        trusted_mtls_fingerprints: Sequence[str] = (),
        require_mtls: bool = False,
        rate_limiter: Optional[LeakyBucketRateLimiter] = None,
        static_admin_token: Optional[str] = None,
    ) -> None:
        self._secrets: list[bytes] = [
            s.encode("utf-8") if isinstance(s, str) else s
            for s in (signing_secret, *previous_secrets)
        ]
        self.allowed_origins = set(allowed_origins)
        self.trusted_mtls_fingerprints = {fp.lower() for fp in trusted_mtls_fingerprints}
        self.require_mtls = require_mtls
        self.rate_limiter = rate_limiter or LeakyBucketRateLimiter()
        self.static_admin_token = static_admin_token

    @staticmethod
    def stdio_context(scopes: Iterable[str] = ALL_SCOPES) -> AuthContext:
        """Implicit local-operator AuthContext for stdio transport."""
        return AuthContext(
            subject="local-stdio-operator",
            scopes=frozenset(scopes),
            transport="stdio",
            client_ip="127.0.0.1",
        )

    def issue_token(
        self,
        subject: str,
        scopes: Iterable[OperationType | str],
        ttl_seconds: int = 3600,
    ) -> str:
        """Issue an HMAC-SHA256 signed scoped bearer token."""
        scope_strs = [s.value if isinstance(s, OperationType) else str(s) for s in scopes]
        payload = {
            "sub": subject,
            "scopes": scope_strs,
            "exp": int(time.time()) + ttl_seconds,
        }
        payload_b64 = (
            base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            )
            .decode("ascii")
            .rstrip("=")
        )
        sig = hmac.new(self._secrets[0], payload_b64.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
        return f"v1.{payload_b64}.{sig_b64}"

    def _verify_hmac_token(self, token: str) -> Optional[dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            return None
        payload_b64, sig_b64 = parts[1], parts[2]
        pad_sig = sig_b64 + "=" * (-len(sig_b64) % 4)
        try:
            provided_sig = base64.urlsafe_b64decode(pad_sig.encode("ascii"))
        except Exception:
            return None

        valid_sig = any(
            hmac.compare_digest(
                hmac.new(secret, payload_b64.encode("ascii"), hashlib.sha256).digest(),
                provided_sig,
            )
            for secret in self._secrets
        )
        if not valid_sig:
            return None

        pad_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
        try:
            payload = json.loads(
                base64.urlsafe_b64decode(pad_payload.encode("ascii")).decode("utf-8")
            )
        except Exception:
            return None

        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload

    def check_cors_origin(self, origin: Optional[str]) -> bool:
        """Validate Origin header against CORS whitelist when configured."""
        if not self.allowed_origins or not origin:
            return True
        return origin in self.allowed_origins

    async def authenticate_request(
        self,
        headers: Mapping[str, str],
        client_cert: Optional[bytes],
        operation: OperationType,
        client_ip: str = "127.0.0.1",
    ) -> AuthContext:
        """Authenticate and authorize an incoming MCP HTTP/SSE request."""
        if not self.rate_limiter.allow(client_ip):
            raise AuthError("Rate limit exceeded", status_code=429)

        norm_headers = {k.lower(): v for k, v in headers.items()}
        origin = norm_headers.get("origin")
        if not self.check_cors_origin(origin):
            raise AuthError(f"CORS origin '{origin}' not allowed", status_code=403)

        mtls_fp: Optional[str] = None
        if client_cert is not None:
            mtls_fp = hashlib.sha256(client_cert).hexdigest().lower()
            if self.trusted_mtls_fingerprints and mtls_fp not in self.trusted_mtls_fingerprints:
                raise AuthError("Untrusted mTLS client certificate", status_code=401)
        elif self.require_mtls:
            raise AuthError("mTLS client certificate required", status_code=401)

        auth_val = norm_headers.get("authorization", "").strip()
        if not auth_val.lower().startswith("bearer "):
            raise AuthError("Missing or invalid Bearer token", status_code=401)
        token = auth_val[7:].strip()

        if self.static_admin_token and hmac.compare_digest(token, self.static_admin_token):
            ctx = AuthContext(
                subject="static-admin",
                scopes=ALL_SCOPES,
                transport="http",
                client_ip=client_ip,
                mtls_fingerprint=mtls_fp,
            )
        else:
            claims = self._verify_hmac_token(token)
            if claims is None:
                raise AuthError("Invalid or expired HMAC token", status_code=401)
            ctx = AuthContext(
                subject=str(claims.get("sub", "unknown")),
                scopes=frozenset(str(s) for s in claims.get("scopes", [])),
                transport="http",
                client_ip=client_ip,
                mtls_fingerprint=mtls_fp,
            )

        if not ctx.has_scope(operation):
            raise AuthError(
                f"Insufficient scope: requires '{operation.value}'",
                status_code=403,
            )

        logger.info(
            "MCP authenticated subject=%s op=%s ip=%s",
            ctx.subject,
            operation.value,
            client_ip,
        )
        return ctx

    def wrap_asgi(
        self,
        app: Any,
        default_operation: OperationType = OperationType.GRAPH_QUERY,
    ) -> Any:
        """Wrap a Starlette/ASGI app with SecurityMiddleware enforcement."""
        middleware = self

        class _ASGIWrapper:
            async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
                if scope.get("type") == "http":
                    headers = {
                        k.decode("latin1"): v.decode("latin1") for k, v in scope.get("headers", [])
                    }
                    client = scope.get("client")
                    client_ip = client[0] if client else "127.0.0.1"
                    client_cert = scope.get("client_cert")
                    try:
                        ctx = await middleware.authenticate_request(
                            headers=headers,
                            client_cert=client_cert,
                            operation=default_operation,
                            client_ip=client_ip,
                        )
                    except AuthError as err:
                        from starlette.responses import Response

                        resp = Response(
                            content=f"Unauthorized: {err}\n"
                            if err.status_code == 401
                            else f"{err}\n",
                            status_code=err.status_code,
                            media_type="text/plain",
                            headers={"WWW-Authenticate": 'Bearer realm="ether-mcp"'}
                            if err.status_code == 401
                            else {},
                        )
                        await resp(scope, receive, send)
                        return
                    token = _CURRENT_AUTH_CONTEXT.set(ctx)
                    try:
                        await app(scope, receive, send)
                    finally:
                        _CURRENT_AUTH_CONTEXT.reset(token)
                    return
                await app(scope, receive, send)

        return _ASGIWrapper()
