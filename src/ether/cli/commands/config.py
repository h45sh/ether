"""Handlers for 'ether config' subcommands."""

from __future__ import annotations

from typing import Any

from ether import paths
from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json
from ether.config import EtherSettings


def handle_config_show(args: Any, context: CliContext) -> int:
    """Print resolved EtherSettings (with secrets redacted unless --unmask)."""
    unmask = bool(getattr(args, "unmask", False))
    settings = context.settings
    payload = settings.model_dump() if unmask else settings.to_redacted_dict()
    payload["_meta"] = {
        "config_path": str(EtherSettings.default_config_path(context.data_dir)),
        "config_exists": EtherSettings.default_config_path(context.data_dir).is_file(),
    }

    if context.is_json:
        print_json(payload)
        return EXIT_SUCCESS

    print(
        f"Config File: {payload['_meta']['config_path']} (exists: {payload['_meta']['config_exists']})"
    )
    for section, values in payload.items():
        if section == "_meta":
            continue
        print(f"\n[{section}]")
        if isinstance(values, dict):
            for k, v in values.items():
                print(f"  {k} = {v!r}")
    return EXIT_SUCCESS


def handle_config_path(args: Any, context: CliContext) -> int:
    """Print the active config.toml path."""
    cfg_path = EtherSettings.default_config_path(context.data_dir)
    if context.is_json:
        print_json({"config_path": str(cfg_path), "exists": cfg_path.is_file()})
    else:
        print(str(cfg_path))
    return EXIT_SUCCESS


def handle_config_init(args: Any, context: CliContext) -> int:
    """Generate a starter config.toml with documented EtherSettings defaults."""
    cfg_path = EtherSettings.default_config_path(context.data_dir)
    force = bool(getattr(args, "force", False))
    if cfg_path.exists() and not force:
        print_error(f"Config already exists at {cfg_path}. Pass --force to overwrite.")
        return EXIT_RUNTIME_ERROR

    s = context.settings
    toml_text = (
        "# Ether unified configuration (CLI > ETHER_* env > config.toml > defaults)\n\n"
        "[gateway]\n"
        f'policy = "{s.gateway.policy}"\n'
        f"allow_loopback = {str(s.gateway.allow_loopback).lower()}\n"
        f"verify_tls = {str(s.gateway.verify_tls).lower()}\n\n"
        "[execution]\n"
        f"default_timeout_sec = {s.execution.default_timeout_sec}\n"
        f"container_fallback = {str(s.execution.container_fallback).lower()}\n"
        f"privilege_drop_caps = {str(s.execution.privilege_drop_caps).lower()}\n\n"
        "[mcp]\n"
        f'transport = "{s.mcp.transport}"\n'
        f'host = "{s.mcp.host}"\n'
        f"port = {s.mcp.port}\n"
        f"rate_limit_capacity = {s.mcp.rate_limit_capacity}\n\n"
        "[graph]\n"
        f"encrypt_at_rest = {str(s.graph.encrypt_at_rest).lower()}\n"
        f"default_ttl_sec = {s.graph.default_ttl_sec}\n\n"
        "[registry]\n"
        f'trust_mode = "{s.registry.trust_mode}"\n'
        f"lazy_load_adapters = {str(s.registry.lazy_load_adapters).lower()}\n"
    )
    paths.atomic_create_file(str(cfg_path), toml_text)
    if context.is_json:
        print_json({"config_path": str(cfg_path), "created": True})
    else:
        print(f"[+] Wrote starter configuration to {cfg_path}")
    return EXIT_SUCCESS
