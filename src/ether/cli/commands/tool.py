"""Handlers for 'ether tool' subcommands."""

import shutil
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


def handle_tool_list(args: Any, context: CliContext) -> int:
    """List all available tool adapters in ToolRegistry."""
    registry = context.get_registry()
    tools = registry.list_tools()

    if context.is_json:
        result = []
        for name in sorted(tools):
            data = registry.get_tool(name)
            manifest = data.get("manifest") if data else None
            adapter = data.get("adapter") if data else None
            meta = getattr(manifest, "meta", None)
            tier = getattr(meta, "execution_tier", "subprocess") if meta else "subprocess"
            binary = getattr(meta, "binary", name) if meta else name

            if tier == "coroutine":
                is_installed = adapter.validate_install() if adapter else True
                display_bin = binary or "native"
            else:
                is_installed = shutil.which(binary) is not None if binary else False
                display_bin = binary or name

            result.append(
                {
                    "name": name,
                    "binary": display_bin,
                    "tier": tier,
                    "execution_tier": tier,
                    "installed": is_installed,
                    "category": getattr(meta, "category", "general") if meta else "general",
                    "description": getattr(meta, "description", "") if meta else "",
                }
            )
        print_json(result)
        return EXIT_SUCCESS

    headers = ["TOOL", "TIER", "BINARY", "INSTALLED", "CATEGORY", "DESCRIPTION"]
    rows = []
    for name in sorted(tools):
        data = registry.get_tool(name)
        manifest = data.get("manifest") if data else None
        adapter = data.get("adapter") if data else None
        meta = getattr(manifest, "meta", None)
        tier = getattr(meta, "execution_tier", "subprocess") if meta else "subprocess"
        binary = getattr(meta, "binary", name) if meta else name

        if tier == "coroutine":
            is_installed = "yes" if (adapter and adapter.validate_install()) else "yes"
            display_bin = binary or "native"
        else:
            is_installed = "yes" if (binary and shutil.which(binary)) else "no"
            display_bin = binary or name

        cat = getattr(meta, "category", "general") if meta else "general"
        desc = getattr(meta, "description", "") if meta else ""
        if len(desc) > 50:
            desc = desc[:47] + "..."
        rows.append([name, tier, display_bin, is_installed, cat, desc])

    print_table(headers, rows)
    return EXIT_SUCCESS


def handle_tool_info(args: Any, context: CliContext) -> int:
    """Display detailed manifest and capabilities for a specific tool."""
    tool_name = getattr(args, "name", None)
    if not tool_name:
        print_error("Tool name is required.")
        return EXIT_RUNTIME_ERROR

    registry = context.get_registry()
    data = registry.get_tool(tool_name)
    if not data or not data.get("manifest"):
        print_error(f"Tool '{tool_name}' not found.")
        return EXIT_RUNTIME_ERROR

    manifest = data["manifest"]
    meta = getattr(manifest, "meta", None)
    tier = getattr(meta, "execution_tier", "subprocess") if meta else "subprocess"
    binary = getattr(meta, "binary", tool_name) if meta else tool_name
    bin_path = shutil.which(binary) if binary else None
    adapter = data.get("adapter")
    is_installed = (
        adapter.validate_install() if (tier == "coroutine" and adapter) else (bin_path is not None)
    )

    info = {
        "name": tool_name,
        "tier": tier,
        "execution_tier": tier,
        "binary": binary or "native",
        "binary_path": bin_path,
        "installed": is_installed,
        "category": getattr(meta, "category", "general") if meta else "general",
        "description": getattr(meta, "description", "") if meta else "",
        "input_accepts": getattr(manifest.input, "accepts", [])
        if hasattr(manifest, "input")
        else [],
        "output_emits": getattr(manifest.output, "emits", [])
        if hasattr(manifest, "output")
        else [],
    }

    if context.is_json:
        print_json(info)
    else:
        print(f"Tool:        {info['name']}")
        print(f"Tier:        {info['tier']}")
        if tier == "coroutine":
            print(
                f"Execution:   Native Async Coroutine ({'Ready' if is_installed else 'Dependencies missing'})"
            )
        else:
            print(
                f"Binary:      {info['binary']} ({'Installed: ' + str(bin_path) if bin_path else 'NOT FOUND'})"
            )
        print(f"Category:    {info['category']}")
        print(f"Description: {info['description']}")
        print(f"Input:       {', '.join(info['input_accepts']) or 'None'}")
        print(f"Output:      {', '.join(info['output_emits']) or 'None'}")

    return EXIT_SUCCESS
