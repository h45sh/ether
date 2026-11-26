"""Handlers for 'ether config' subcommands."""

from __future__ import annotations

from typing import Any

from ether.cli.context import EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_json
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
