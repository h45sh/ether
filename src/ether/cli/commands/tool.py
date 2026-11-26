"""Handlers for 'ether tool' subcommands."""

import shutil
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


def handle_tool_list(args: Any, context: CliContext) -> int:
    """List all available tool adapters in ToolRegistry."""
    registry = context.get_registry()
    entries = registry.list_tool_summaries()

    if context.is_json:
        print_json(entries)
        return EXIT_SUCCESS

    headers = ["TOOL", "TIER", "BINARY", "INSTALLED", "CATEGORY", "DESCRIPTION"]
    rows = []
    for entry in entries:
        desc = entry.get("description", "")
        if len(desc) > 50:
            desc = desc[:47] + "..."
        installed_str = "yes" if entry.get("installed") else "no"
        rows.append(
            [
                entry["name"],
                entry.get("tier", "subprocess"),
                entry.get("binary", entry["name"]),
                installed_str,
                entry.get("category", "general"),
                desc,
            ]
        )

    print_table(headers, rows)
    return EXIT_SUCCESS


def handle_tool_search(args: Any, context: CliContext) -> int:
    """Search registered tools by keyword, accepted schema, or produced schema."""
    registry = context.get_registry()
    matches = registry.search_tools(
        query=getattr(args, "query", None),
        accepts=getattr(args, "accepts", None),
        produces=getattr(args, "produces", None),
        include_profiles=True,
    )

    if context.is_json:
        print_json(matches)
        return EXIT_SUCCESS

    headers = ["TOOL", "TIER", "INSTALLED", "PROFILES", "SUMMARY"]
    rows = []
    for entry in matches:
        profs = ",".join(sorted((entry.get("profiles") or {}).keys())) or "-"
        summary = entry.get("one_line_summary") or entry.get("description", "")
        if len(summary) > 55:
            summary = summary[:52] + "..."
        rows.append(
            [
                entry["name"],
                entry.get("tier", "subprocess"),
                "yes" if entry.get("installed") else "no",
                profs,
                summary,
            ]
        )

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

    from ether.gateway.preflight import get_tool_target_guidance

    recommended_flags: list[dict[str, Any]] = []
    profiles = getattr(manifest, "profiles", None) or {}
    for profile_name, flag_vec in profiles.items():
        recommended_flags.append({"profile": profile_name, "flags": list(flag_vec)})

    info = {
        "name": tool_name,
        "tier": tier,
        "execution_tier": tier,
        "binary": binary or "native",
        "binary_path": bin_path,
        "installed": is_installed,
        "category": getattr(meta, "category", "general") if meta else "general",
        "one_line_summary": getattr(meta, "one_line_summary", "") if meta else "",
        "description": getattr(meta, "description", "") if meta else "",
        "input_accepts": manifest.input.get("accepts", [])
        if isinstance(getattr(manifest, "input", None), dict)
        else [],
        "output_emits": (
            manifest.output.get("produces") or manifest.output.get("emits", [])
            if isinstance(getattr(manifest, "output", None), dict)
            else []
        ),
        "recommended_flags": recommended_flags,
        "target_guidance": get_tool_target_guidance(tool_name),
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
