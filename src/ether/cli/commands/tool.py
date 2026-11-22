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
            binary = getattr(manifest, "binary", name) if manifest else name
            is_installed = shutil.which(binary) is not None
            result.append(
                {
                    "name": name,
                    "binary": binary,
                    "installed": is_installed,
                    "category": getattr(manifest, "category", "general") if manifest else "general",
                    "description": getattr(manifest, "description", "") if manifest else "",
                }
            )
        print_json(result)
        return EXIT_SUCCESS

    headers = ["TOOL", "BINARY", "INSTALLED", "CATEGORY", "DESCRIPTION"]
    rows = []
    for name in sorted(tools):
        data = registry.get_tool(name)
        manifest = data.get("manifest") if data else None
        binary = getattr(manifest, "binary", name) if manifest else name
        is_installed = "yes" if shutil.which(binary) else "no"
        cat = getattr(manifest, "category", "general") if manifest else "general"
        desc = getattr(manifest, "description", "") if manifest else ""
        if len(desc) > 50:
            desc = desc[:47] + "..."
        rows.append([name, binary, is_installed, cat, desc])

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
    binary = getattr(manifest, "binary", tool_name)
    bin_path = shutil.which(binary)

    info = {
        "name": tool_name,
        "binary": binary,
        "binary_path": bin_path,
        "installed": bin_path is not None,
        "category": getattr(manifest, "category", "general"),
        "description": getattr(manifest, "description", ""),
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
        print(
            f"Binary:      {info['binary']} ({'Installed: ' + str(bin_path) if bin_path else 'NOT FOUND'})"
        )
        print(f"Category:    {info['category']}")
        print(f"Description: {info['description']}")
        print(f"Input:       {', '.join(info['input_accepts']) or 'None'}")
        print(f"Output:      {', '.join(info['output_emits']) or 'None'}")

    return EXIT_SUCCESS
