# PROTECTED FILE — See docs/CONTRIBUTING.md before modifying.
# Changes to this file require team agreement.
"""Dynamic tool discovery and loading."""

import tomllib
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any, Dict, List, Optional

from ether.registry.adapter import ToolAdapter
from ether.registry.manifest import Manifest


class ToolRegistry:
    """Discovers and loads tool plugins from the tools/ directory."""

    def __init__(self, tools_dir: Optional[str] = None):
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

    def load_tools(self):
        """Scan the tools directory and load all valid plugins."""
        self.tools = {}
        self.load_errors = {}

        if not self.tools_dir.exists():
            return

        for tool_path in sorted(self.tools_dir.iterdir(), key=lambda p: p.name):
            if tool_path.is_dir():
                manifest_path = tool_path / "manifest.toml"
                adapter_path = tool_path / "adapter.py"

                if manifest_path.exists() and adapter_path.exists():
                    try:
                        # 1. Load and validate manifest
                        with open(manifest_path, "rb") as f:
                            data = tomllib.load(f)
                            manifest = Manifest(**data)

                        # 2. Dynamically load the adapter class
                        adapter_instance = self._load_adapter(adapter_path)

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

    def _load_adapter(self, adapter_path: Path) -> Optional[ToolAdapter]:
        """Import the adapter.py module and instantiate the ToolAdapter class."""
        try:
            module_name = f"tools.{adapter_path.parent.name}.adapter"
            spec = spec_from_file_location(module_name, adapter_path)
            if spec and spec.loader:
                module = module_from_spec(spec)
                spec.loader.exec_module(module)

                # Look for a subclass of ToolAdapter
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, ToolAdapter)
                        and attr is not ToolAdapter
                    ):
                        return attr()
            return None
        except Exception:
            # Re-raise to let load_tools capture the full context
            raise

    def get_tool(self, name: str) -> Optional[Dict]:
        """Return the manifest and adapter instance for a named tool."""
        return self.tools.get(name)

    def list_tools(self) -> List[str]:
        """Return a list of loaded tool names."""
        return list(self.tools.keys())

    def get_tool_summary(self, name: str) -> Optional[Dict[str, Any]]:
        """Return a structured metadata and installation summary for a tool, calling validate_install() once."""
        data = self.tools.get(name)
        if not data:
            return None
        manifest = data["manifest"]
        adapter = data["adapter"]
        meta = manifest.meta
        installed = bool(adapter.validate_install())
        return {
            "name": meta.name,
            "description": meta.description,
            "one_line_summary": meta.one_line_summary,
            "category": meta.category,
            "categories": list(meta.categories),
            "binary": meta.binary or meta.name,
            "tier": meta.execution_tier,
            "execution_tier": meta.execution_tier,
            "target_types": list(manifest.input.get("target_types", [])),
            "accepts": list(manifest.input.get("accepts", [])),
            "produces": list(manifest.output.get("produces", [])),
            "installed": installed,
        }

    def list_tool_summaries(self) -> List[Dict[str, Any]]:
        """Return structured summaries for all loaded tools."""
        summaries: List[Dict[str, Any]] = []
        for name in self.list_tools():
            summary = self.get_tool_summary(name)
            if summary is not None:
                summaries.append(summary)
        return summaries

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
        # optional diagnostics

        self.refresh_if_changed()
        return {
            name: {
                "status": "ok" if data["adapter"].validate_install() else "error",
                "healthy": data["adapter"].validate_install(),
                "installed": data["adapter"].validate_install(),
            }
            for name, data in self.tools.items()
        }
