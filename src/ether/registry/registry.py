# PROTECTED FILE — See docs/CONTRIBUTING.md before modifying.
# Changes to this file require team agreement.
"""Dynamic tool discovery and loading."""

import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional

from ether.registry.adapter import ToolAdapter, is_binary_available
from ether.registry.manifest import Manifest


class _LazyToolEntry(dict):
    """Dict-compatible tool entry that lazily loads its adapter only when 'adapter' is accessed."""

    def __init__(self, registry: "ToolRegistry", tool_name: str, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._registry = registry
        self._tool_name = tool_name

    def __getitem__(self, key: str) -> Any:
        if key == "adapter" and super().get("adapter") is None:
            self._registry._ensure_adapter(self._tool_name)
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "adapter" and super().get("adapter") is None:
            self._registry._ensure_adapter(self._tool_name)
        return super().get(key, default)


class ToolRegistry:
    """Discovers and loads tool plugins from the tools/ directory."""

    def __init__(self, tools_dir: Optional[str] = None, settings: Optional[Any] = None):
        self._settings = settings
        if tools_dir is None:
            # 1. First check if project_root / "tools" exists (development/repo checkout)
            project_root = Path(__file__).parent.parent.parent
            candidate = project_root / "tools"
            if candidate.exists() and candidate.is_dir():
                self.tools_dir = candidate
            else:
                # 2. Fall back to imported tools package location (installed package mode)
                try:
                    import tools

                    self.tools_dir = Path(tools.__file__).parent
                except Exception:
                    self.tools_dir = candidate
        else:
            self.tools_dir = Path(tools_dir)

        self.tools: Dict[str, Dict] = {}
        self.load_errors: Dict[str, str] = {}

    def _lazy_enabled(self) -> bool:
        reg_cfg = getattr(self._settings, "registry", None)
        return bool(getattr(reg_cfg, "lazy_load_adapters", True))

    def load_tools(self):
        """Scan the tools directory and register tool manifests (lazy-loading adapters by default)."""
        self.tools = {}
        self.load_errors = {}

        if not self.tools_dir.exists():
            return

        lazy = self._lazy_enabled()
        for tool_path in sorted(self.tools_dir.iterdir(), key=lambda p: p.name):
            if tool_path.is_dir():
                manifest_path = tool_path / "manifest.toml"
                adapter_path = tool_path / "adapter.py"

                if manifest_path.exists() and adapter_path.exists():
                    try:
                        with open(manifest_path, "rb") as f:
                            data = tomllib.load(f)
                            manifest = Manifest(**data)

                        if lazy:
                            self.tools[manifest.meta.name] = _LazyToolEntry(
                                self,
                                manifest.meta.name,
                                {
                                    "manifest": manifest,
                                    "adapter": None,
                                    "path": tool_path,
                                    "_adapter_path": adapter_path,
                                    "_manifest_path": manifest_path,
                                },
                            )
                        else:
                            adapter_instance = self._load_adapter(adapter_path, manifest_path)
                            if adapter_instance:
                                if hasattr(manifest.meta, "execution_tier"):
                                    adapter_instance.execution_tier = manifest.meta.execution_tier
                                self.tools[manifest.meta.name] = {
                                    "manifest": manifest,
                                    "adapter": adapter_instance,
                                    "path": tool_path,
                                }
                            else:
                                self.load_errors[tool_path.name] = (
                                    "No ToolAdapter subclass found in adapter.py"
                                )
                    except Exception as e:
                        self.load_errors[tool_path.name] = str(e)

    def _load_adapter(
        self, adapter_path: Path, manifest_path: Optional[Path] = None
    ) -> Optional[ToolAdapter]:
        """Verify and import the adapter.py module via PluginLoader and instantiate ToolAdapter."""
        from ether.registry.loader import PluginLoader, PluginTrustMode

        m_path = manifest_path or (adapter_path.parent / "manifest.toml")
        reg_cfg = getattr(self._settings, "registry", None)
        mode_str = str(getattr(reg_cfg, "trust_mode", "dev")).lower()
        trust_mode = (
            PluginTrustMode.STRICT if mode_str == "strict" else PluginTrustMode.DEV
        )
        raw_keys = getattr(reg_cfg, "trusted_public_keys", None) or []
        trusted_keys = [
            bytes.fromhex(k) if len(k) == 64 else k.encode("utf-8") for k in raw_keys
        ] or None
        loader = PluginLoader(trust_mode=trust_mode, trusted_public_keys=trusted_keys)
        return loader.load_verified_adapter(adapter_path, m_path)

    def is_adapter_loaded(self, name: str) -> bool:
        """Return True if the adapter module for `name` has already been imported."""
        entry = self.tools.get(name)
        return bool(entry and dict.get(entry, "adapter") is not None)

    def _ensure_adapter(self, name: str) -> Optional[Dict]:
        """Lazily load and verify adapter.py for a registered tool on first use."""
        entry = self.tools.get(name)
        if not entry:
            return None
        if dict.get(entry, "adapter") is None:
            adapter_path = entry.get("_adapter_path") or (entry["path"] / "adapter.py")
            manifest_path = entry.get("_manifest_path") or (entry["path"] / "manifest.toml")
            adapter_instance = self._load_adapter(adapter_path, manifest_path)
            if adapter_instance is None:
                self.load_errors[name] = "No ToolAdapter subclass found in adapter.py"
                return None
            manifest = entry["manifest"]
            if hasattr(manifest.meta, "execution_tier"):
                adapter_instance.execution_tier = manifest.meta.execution_tier
            entry["adapter"] = adapter_instance
        return entry

    def get_tool(self, name: str) -> Optional[Dict]:
        """Return the manifest and lazily-loaded adapter instance for a named tool."""
        return self._ensure_adapter(name)

    def list_tools(self) -> List[str]:
        """Return a list of loaded tool names."""
        return list(self.tools.keys())

    def get_tool_summary(self, name: str, include_profiles: bool = True) -> Optional[Dict[str, Any]]:
        """Return a structured metadata and installation summary without forcing lazy adapter imports for CLI binaries."""
        data = self.tools.get(name)
        if not data:
            return None
        manifest = data["manifest"]
        meta = manifest.meta
        tier = getattr(meta, "execution_tier", "subprocess")
        binary = meta.binary or meta.name

        if dict.get(data, "adapter") is not None:
            installed = bool(dict.get(data, "adapter").validate_install())
        elif tier == "coroutine":
            loaded = self._ensure_adapter(name)
            installed = bool(loaded and loaded["adapter"].validate_install())
        else:
            installed = bool(is_binary_available(binary))

        summary: Dict[str, Any] = {
            "name": meta.name,
            "description": meta.description,
            "one_line_summary": meta.one_line_summary,
            "category": meta.category,
            "categories": list(meta.categories),
            "binary": binary,
            "tier": tier,
            "execution_tier": tier,
            "target_types": list(manifest.input.get("target_types", [])),
            "accepts": list(manifest.input.get("accepts", [])),
            "produces": list(manifest.output.get("produces", [])),
            "installed": installed,
        }
        if include_profiles:
            summary["profiles"] = {k: list(v) for k, v in (manifest.profiles or {}).items()}
        return summary

    def list_tool_summaries(self, include_profiles: bool = True) -> List[Dict[str, Any]]:
        """Return structured summaries for all loaded tools."""
        summaries: List[Dict[str, Any]] = []
        for name in self.list_tools():
            summary = self.get_tool_summary(name, include_profiles=include_profiles)
            if summary is not None:
                summaries.append(summary)
        return summaries

    def search_tools(
        self,
        query: Optional[str] = None,
        accepts: Optional[str] = None,
        produces: Optional[str] = None,
        include_profiles: bool = True,
    ) -> List[Dict[str, Any]]:
        """Search registered tools by keyword, accepted schema, or produced schema."""
        q = (query or "").strip().lower()
        acc = (accepts or "").strip().lower()
        prod = (produces or "").strip().lower()

        matches: List[Dict[str, Any]] = []
        for summary in self.list_tool_summaries(include_profiles=include_profiles):
            if acc and acc not in [s.lower() for s in summary.get("accepts", [])]:
                continue
            if prod and prod not in [s.lower() for s in summary.get("produces", [])]:
                continue
            if q:
                haystack = " ".join(
                    [
                        summary.get("name", ""),
                        summary.get("one_line_summary", ""),
                        summary.get("description", ""),
                        summary.get("category", ""),
                        " ".join(summary.get("categories", [])),
                    ]
                ).lower()
                if q not in haystack:
                    continue
            matches.append(summary)
        return matches

    def find_tools_for_input(self, schema_type: str) -> List[str]:
        """Find all tools that accept a specific finding type as input."""
        matching = []
        for name, data in self.tools.items():
            if schema_type in data["manifest"].input.get("accepts", []):
                matching.append(name)
        return matching

    def refresh_if_changed(self) -> bool:
        """Scan directory and reload plugins only if tool directory structure on disk changed."""
        if not self.tools_dir.exists():
            if self.tools or self.load_errors:
                self.tools = {}
                self.load_errors = {}
                return True
            return False

        try:
            current_dirs = {
                p.name
                for p in self.tools_dir.iterdir()
                if p.is_dir() and not p.name.startswith((".", "_"))
            }
            loaded_dirs = {v["path"].name for v in self.tools.values() if v.get("path")}
            if current_dirs != loaded_dirs:
                self.load_tools()
                return True
        except Exception:
            pass
        return False

    def check_health(self) -> Dict[str, Dict[str, Any]]:
        """Return comprehensive health and installation diagnostics for all registered tools."""
        self.refresh_if_changed()
        results: Dict[str, Dict[str, Any]] = {}
        for name in self.list_tools():
            entry = self._ensure_adapter(name)
            installed = bool(entry and entry["adapter"].validate_install())
            results[name] = {
                "status": "ok" if installed else "error",
                "healthy": installed,
                "installed": installed,
            }
        return results
