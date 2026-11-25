"""Handlers for 'ether tool' subcommands."""

import shutil
from typing import Any

from ether.cli.context import EXIT_RUNTIME_ERROR, EXIT_SUCCESS, CliContext
from ether.cli.formatters import print_error, print_json, print_table


def _collect_tool_entries(registry: Any) -> list[dict[str, Any]]:
    """Collect normalized tool metadata using ToolRegistry summary if present, with safe fallback."""
    summary_fn = getattr(registry, "list_tool_summaries", None) or getattr(
        registry, "summary", None
    )
    if callable(summary_fn):
        try:
            raw_summary = summary_fn()
            if isinstance(raw_summary, list):
                for s in raw_summary:
                    if "tier" not in s and "execution_tier" in s:
                        s["tier"] = s["execution_tier"]
                return raw_summary
        except Exception:
            pass

    result = []
    for name in sorted(registry.list_tools()):
        data = registry.get_tool(name)
        manifest = data.get("manifest") if data else None
        adapter = data.get("adapter") if data else None
        meta = getattr(manifest, "meta", None)
        tier = getattr(meta, "execution_tier", "subprocess") if meta else "subprocess"
        binary = getattr(meta, "binary", name) if meta else name

        if tier == "coroutine":
            is_installed = bool(adapter and adapter.validate_install())
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
    return result


def handle_tool_list(args: Any, context: CliContext) -> int:
    """List all available tool adapters in ToolRegistry."""
    registry = context.get_registry()
    entries = _collect_tool_entries(registry)

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
    power_cfg = getattr(manifest, "power", None)
    if power_cfg and getattr(power_cfg, "suggests", None):
        recommended_flags.extend(dict(s) for s in power_cfg.suggests)
    learning_cfg = getattr(manifest, "learning", None)
    if learning_cfg and getattr(learning_cfg, "recipes", None):
        for r in learning_cfg.recipes:
            recommended_flags.append(
                {
                    "name": r.name,
                    "difficulty": r.difficulty,
                    "description": r.description,
                    "flags": r.flags,
                }
            )

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
