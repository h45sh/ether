"""Unified, typed configuration deep module for Ether (ether.config).

Precedence:
    CLI flags > ETHER_* environment variables > $ETHER_DATA_DIR/config.toml > defaults
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field


def _parse_bool(raw: str) -> bool:
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _parse_csv_list(raw: str) -> List[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


class PathsSettings(BaseModel):
    """Filesystem and asset directory settings."""

    model_config = ConfigDict(extra="forbid")

    data_dir: Optional[str] = Field(
        default=None,
        description="Unified Ether data directory (defaults to ~/.ether; env: ETHER_DATA_DIR).",
    )
    db_path: Optional[str] = Field(
        default=None,
        description="SQLite database path (defaults to <data_dir>/ether.db).",
    )
    tools_dir: Optional[str] = Field(
        default=None,
        description="Directory containing pluggable tool adapters (defaults to bundled tools/).",
    )
    wordlists_dir: Optional[str] = Field(
        default=None,
        description="Override root directory for wordlist resolution (env: ETHER_WORDLISTS_DIR).",
    )


class ExecutionSettings(BaseModel):
    """Process supervision, ring buffer, tarpit guard, pipeline, and privilege settings."""

    model_config = ConfigDict(extra="forbid")

    default_timeout_sec: float = Field(
        default=120.0,
        ge=0.1,
        description="Default per-action execution timeout in seconds.",
    )
    ring_buffer_bytes: int = Field(
        default=2 * 1024 * 1024,
        ge=4096,
        description="Maximum per-job in-memory ring buffer size in bytes (2 MiB).",
    )
    ring_buffer_chunks: int = Field(
        default=5000,
        ge=1,
        description="Maximum number of stdout/stderr chunks retained in memory per job.",
    )
    event_log_max_chars: int = Field(
        default=200_000,
        ge=1024,
        description="Maximum output characters persisted inline in event_log before head/tail truncation.",
    )
    stream_chunk_bytes: int = Field(
        default=65536,
        ge=1024,
        description="Subprocess stream read chunk size in bytes.",
    )
    loop_yield_sec: float = Field(
        default=0.01,
        ge=0.0,
        description="Asyncio event loop yield interval inside tight stream reader loops.",
    )
    tarpit_window_sec: float = Field(
        default=15.0,
        ge=1.0,
        description="Sliding window in seconds for StreamTarpitGuard throughput checks.",
    )
    tarpit_min_bps: float = Field(
        default=10.0,
        ge=0.0,
        description="Minimum bytes/sec before StreamTarpitGuard flags a delay tarpit.",
    )
    pipeline_max_concurrent: int = Field(
        default=50,
        ge=1,
        description="Maximum concurrent stages in PipelineEngine.",
    )
    pipeline_queue_size: int = Field(
        default=500,
        ge=1,
        description="Maximum bounded queue depth in PipelineEngine.",
    )
    container_fallback: bool = Field(
        default=False,
        description="Dispatch missing host binaries inside a hardened container (env: ETHER_CONTAINER_FALLBACK).",
    )
    container_image: str = Field(
        default="ghcr.io/ether/arsenal:0.1.3",
        description="Container image used when container_fallback is enabled (env: ETHER_CONTAINER_IMAGE).",
    )
    privilege_drop_caps: bool = Field(
        default=False,
        description="Drop Linux ambient capabilities and set PR_SET_NO_NEW_PRIVS on supervisor execution.",
    )
    privilege_use_netns: bool = Field(
        default=False,
        description="Wrap scanner subprocesses in rootless unshare network namespaces when supported.",
    )
    privilege_uds_path: Optional[str] = Field(
        default=None,
        description="Optional Unix domain socket path for isolated ether-worker execution.",
    )


class GatewaySettings(BaseModel):
    """Policy gating, scope validation, and pinned HTTP transport settings."""

    model_config = ConfigDict(extra="forbid")

    policy: Literal["safe", "unrestricted"] = Field(
        default="safe",
        description="Default ActionGateway policy mode ('safe' or 'unrestricted').",
    )
    allow_loopback: bool = Field(
        default=False,
        description="Allow scanning loopback targets (127.0.0.1, ::1) under safe policy.",
    )
    allow_metadata: bool = Field(
        default=False,
        description="Allow cloud metadata endpoints under safe policy (not recommended).",
    )
    allow_link_local: bool = Field(
        default=False,
        description="Allow link-local addresses (169.254.0.0/16) under safe policy.",
    )
    dns_timeout_sec: float = Field(
        default=1.0,
        ge=0.1,
        description="DNS resolution timeout in seconds for ScopeValidator and PinnedTransport.",
    )
    verify_tls: bool = Field(
        default=True,
        description="Verify TLS certificates by default in PinnedTransport.",
    )
    http_timeout_sec: float = Field(
        default=10.0,
        ge=0.1,
        description="Default HTTP client timeout in seconds for PinnedTransport.",
    )
    max_redirects: int = Field(
        default=5,
        ge=0,
        description="Maximum validated redirect hops in PinnedTransport.",
    )


class McpSettings(BaseModel):
    """Model Context Protocol (MCP) server, transport, and RBAC security settings."""

    model_config = ConfigDict(extra="forbid")

    transport: Literal["stdio", "sse"] = Field(
        default="stdio",
        description="MCP server transport mode ('stdio' or 'sse').",
    )
    host: str = Field(
        default="127.0.0.1",
        description="Bind host for MCP SSE transport.",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Bind port for MCP SSE transport.",
    )
    auth_token: Optional[str] = Field(
        default=None,
        description="HMAC signing secret / bearer token for MCP SSE (env: ETHER_MCP_AUTH_TOKEN).",
    )
    previous_secrets: List[str] = Field(
        default_factory=list,
        description="Previous HMAC signing secrets accepted during key rotation grace windows.",
    )
    rate_limit_capacity: int = Field(
        default=60,
        ge=1,
        description="Per-IP leaky-bucket burst capacity for MCP SSE requests.",
    )
    rate_limit_refill_per_sec: float = Field(
        default=2.0,
        ge=0.1,
        description="Per-IP leaky-bucket token refill rate per second.",
    )
    token_ttl_sec: int = Field(
        default=3600,
        ge=60,
        description="Default TTL in seconds for issued scoped MCP HMAC tokens.",
    )
    allowed_origins: List[str] = Field(
        default_factory=list,
        description="Strict CORS origin allowlist for MCP SSE transport.",
    )
    require_mtls: bool = Field(
        default=False,
        description="Require verified mTLS client certificate fingerprints on MCP SSE.",
    )
    trusted_mtls_fingerprints: List[str] = Field(
        default_factory=list,
        description="Allowlisted SHA-256 client certificate fingerprints for MCP mTLS.",
    )


class GraphSettings(BaseModel):
    """GraphStore, WriteQueue, cryptography, temporal decay, and analytics settings."""

    model_config = ConfigDict(extra="forbid")

    encrypt_at_rest: bool = Field(
        default=True,
        description="Enable ChaCha20-Poly1305 field-level encryption on persistent GraphStore databases.",
    )
    write_batch_window_sec: float = Field(
        default=0.001,
        ge=0.0,
        description="WriteQueue batch coalescing window in seconds.",
    )
    write_max_batch_size: int = Field(
        default=500,
        ge=1,
        description="Maximum operations coalesced in a single WriteQueue batch.",
    )
    read_pool_size: int = Field(
        default=10,
        ge=1,
        description="Maximum concurrent read-only SQLite connections in GraphStore.",
    )
    sqlite_busy_timeout_ms: int = Field(
        default=5000,
        ge=100,
        description="SQLite PRAGMA busy_timeout in milliseconds.",
    )
    default_ttl_sec: int = Field(
        default=3600,
        ge=1,
        description="Default node TTL in seconds before temporal decay marks it stale.",
    )
    prune_max_age_sec: int = Field(
        default=604800,
        ge=60,
        description="Default max age in seconds (7 days) when pruning stale nodes.",
    )
    embedding_dim: int = Field(
        default=384,
        ge=32,
        description="Vector embedding dimensionality for semantic search.",
    )
    onnx_model_path: Optional[str] = Field(
        default=None,
        description="Optional ONNX embedding model path (env: ETHER_ONNX_MODEL_PATH).",
    )
    deception_base_confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Baseline confidence score for GraphAnalyticsEngine deception evaluation.",
    )


class RegistrySettings(BaseModel):
    """ToolRegistry and PluginLoader attestation settings."""

    model_config = ConfigDict(extra="forbid")

    trust_mode: Literal["dev", "strict"] = Field(
        default="dev",
        description="Plugin attestation trust mode ('dev' or 'strict'; env: ETHER_PLUGIN_TRUST_MODE).",
    )
    trusted_public_keys: List[str] = Field(
        default_factory=list,
        description="Base64/hex Ed25519 public keys trusted for strict adapter verification.",
    )
    lazy_load_adapters: bool = Field(
        default=True,
        description="Defer importing and verifying adapter.py until a tool is executed.",
    )


class StorageSettings(BaseModel):
    """Forensic log spooling, retention, and timeline compaction settings."""

    model_config = ConfigDict(extra="forbid")

    max_disk_mb: int = Field(
        default=1000,
        ge=1,
        description="Maximum retained log disk budget in MB before pruning.",
    )
    max_age_days: int = Field(
        default=30,
        ge=1,
        description="Maximum retained log age in days.",
    )
    compress_older_than_sec: float = Field(
        default=3600.0,
        ge=60.0,
        description="Compress raw log files older than this many seconds.",
    )
    log_spool_buffering_bytes: int = Field(
        default=65536,
        ge=4096,
        description="Write buffer size in bytes for LogSpooler.",
    )
    timeline_keep_closed_events: int = Field(
        default=500,
        ge=0,
        description="Number of recent closed events retained during ActionTimelineRepository compaction.",
    )


class LoggingSettings(BaseModel):
    """System logging and FlightRecorder breadcrumb settings."""

    model_config = ConfigDict(extra="forbid")

    debug: bool = Field(
        default=False,
        description="Enable verbose DEBUG logging (env: ETHER_DEBUG).",
    )
    flight_recorder_maxlen: int = Field(
        default=200,
        ge=10,
        description="Maximum breadcrumbs stored in FlightRecorder ring buffer.",
    )
    log_rotate_max_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=65536,
        description="Maximum system log file size in bytes before rotation (5 MiB).",
    )
    log_rotate_backups: int = Field(
        default=3,
        ge=0,
        description="Number of rotated system log backup files to retain.",
    )


class TelemetrySettings(BaseModel):
    """GraphTelemetryCompiler token budgeting and query defaults."""

    model_config = ConfigDict(extra="forbid")

    default_token_budget: int = Field(
        default=4000,
        ge=100,
        description="Default token budget for telemetry snapshots and findings summarization.",
    )
    chars_per_token: float = Field(
        default=4.0,
        ge=1.0,
        description="Estimated characters per token for telemetry budget accounting.",
    )
    default_query_limit: int = Field(
        default=100,
        ge=1,
        description="Default maximum rows returned by graph queries.",
    )


class EtherSettings(BaseModel):
    """Root configuration model unifying all Ether subsystems."""

    model_config = ConfigDict(extra="forbid")

    paths: PathsSettings = Field(default_factory=PathsSettings)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    gateway: GatewaySettings = Field(default_factory=GatewaySettings)
    mcp: McpSettings = Field(default_factory=McpSettings)
    graph: GraphSettings = Field(default_factory=GraphSettings)
    registry: RegistrySettings = Field(default_factory=RegistrySettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    telemetry: TelemetrySettings = Field(default_factory=TelemetrySettings)

    @classmethod
    def default_config_path(cls, data_dir: Optional[str] = None) -> Path:
        """Return default config.toml path without creating directories."""
        base = data_dir or os.environ.get("ETHER_DATA_DIR") or os.path.expanduser("~/.ether")
        return Path(os.path.abspath(os.path.expanduser(base))) / "config.toml"

    @classmethod
    def load(
        cls,
        data_dir: Optional[str] = None,
        config_path: Optional[str | Path] = None,
        cli_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> "EtherSettings":
        """Load settings with precedence: CLI > ETHER_* env > config.toml > defaults."""
        env_map = os.environ if env is None else env
        resolved_data_dir = data_dir or env_map.get("ETHER_DATA_DIR")
        cfg_file = Path(config_path) if config_path else cls.default_config_path(resolved_data_dir)

        merged: Dict[str, Any] = {}
        if cfg_file.is_file():
            with open(cfg_file, "rb") as f:
                raw_toml = tomllib.load(f)
            if isinstance(raw_toml, dict):
                merged = {k: dict(v) if isinstance(v, dict) else v for k, v in raw_toml.items()}

        cls._apply_env_overrides(merged, env_map)

        if cli_overrides:
            for section, values in cli_overrides.items():
                if not isinstance(values, dict):
                    continue
                sec_dict = merged.setdefault(section, {})
                for k, v in values.items():
                    if v is not None:
                        sec_dict[k] = v

        if data_dir:
            merged.setdefault("paths", {})["data_dir"] = data_dir

        return cls.model_validate(merged)

    @classmethod
    def _apply_env_overrides(cls, target: Dict[str, Any], env_map: Mapping[str, str]) -> None:
        """Apply flat legacy ETHER_* env vars and structured ETHER_<SECTION>__<KEY> overrides."""
        legacy_map: Dict[str, tuple[str, str, Callable[[str], Any]]] = {
            "ETHER_DATA_DIR": ("paths", "data_dir", str),
            "ETHER_WORDLISTS_DIR": ("paths", "wordlists_dir", str),
            "ETHER_MCP_AUTH_TOKEN": ("mcp", "auth_token", str),
            "ETHER_ONNX_MODEL_PATH": ("graph", "onnx_model_path", str),
            "ETHER_CONTAINER_FALLBACK": ("execution", "container_fallback", _parse_bool),
            "ETHER_CONTAINER_IMAGE": ("execution", "container_image", str),
            "ETHER_DEBUG": ("logging", "debug", _parse_bool),
            "ETHER_PLUGIN_TRUST_MODE": ("registry", "trust_mode", lambda s: s.strip().lower()),
        }
        for env_key, (sec, field_name, caster) in legacy_map.items():
            raw = env_map.get(env_key)
            if raw is not None and raw != "":
                target.setdefault(sec, {})[field_name] = caster(raw)

        section_models = cls.model_fields
        for env_key, raw in env_map.items():
            if not env_key.startswith("ETHER_") or "__" not in env_key:
                continue
            rest = env_key[len("ETHER_") :]
            sec_raw, field_raw = rest.split("__", 1)
            sec = sec_raw.lower()
            field_name = field_raw.lower()
            if sec not in section_models:
                continue
            sec_model: Any = section_models[sec].annotation
            if sec_model is None or not hasattr(sec_model, "model_fields"):
                continue
            if field_name not in sec_model.model_fields:
                continue
            field_info = sec_model.model_fields[field_name]
            target.setdefault(sec, {})[field_name] = cls._coerce_env_value(raw, field_info.annotation)

    @staticmethod
    def _coerce_env_value(raw: str, annotation: Any) -> Any:
        ann_str = str(annotation)
        if "bool" in ann_str:
            return _parse_bool(raw)
        if "int" in ann_str and "float" not in ann_str:
            return int(raw)
        if "float" in ann_str:
            return float(raw)
        if "List[" in ann_str or "list[" in ann_str:
            return _parse_csv_list(raw)
        return raw

    def to_redacted_dict(self) -> Dict[str, Any]:
        """Return settings dictionary with sensitive tokens redacted."""
        data = self.model_dump()
        if data.get("mcp", {}).get("auth_token"):
            data["mcp"]["auth_token"] = "********"
        if data.get("mcp", {}).get("previous_secrets"):
            data["mcp"]["previous_secrets"] = ["********" for _ in data["mcp"]["previous_secrets"]]
        return data
