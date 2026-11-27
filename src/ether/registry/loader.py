"""Cryptographic plugin attestation and AST-sandboxed adapter loader (ether.registry.loader)."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import types
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ether.registry.adapter import ToolAdapter


class PluginTrustMode(str, Enum):
    """Trust policy for adapter loading."""

    STRICT = "strict"
    DEV = "dev"


class PluginSecurityError(PermissionError):
    """Raised when an adapter fails signature, hash, or AST safety checks."""


_FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
_FORBIDDEN_MODULES = frozenset({"ctypes", "pty"})


def _check_adapter_ast(source: str, adapter_path: Path) -> None:
    """Statically verify adapter AST does not contain dangerous dynamic code execution."""
    try:
        tree = ast.parse(source, filename=str(adapter_path))
    except SyntaxError as e:
        raise PluginSecurityError(f"Syntax error in adapter '{adapter_path}': {e}") from e

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in _FORBIDDEN_CALLS:
                raise PluginSecurityError(
                    f"Forbidden dynamic call '{node.func.id}()' in '{adapter_path}'."
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _FORBIDDEN_MODULES:
                    raise PluginSecurityError(
                        f"Forbidden module import '{alias.name}' in '{adapter_path}'."
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _FORBIDDEN_MODULES:
                raise PluginSecurityError(
                    f"Forbidden module import '{node.module}' in '{adapter_path}'."
                )


def _find_bundled_tools_root() -> Optional[Path]:
    """Locate the first-party bundled tools directory in wheel or source layouts."""
    here = Path(__file__).resolve()
    for parent_idx in (2, 3):
        if parent_idx < len(here.parents):
            candidate = here.parents[parent_idx] / "tools"
            if (candidate / "bundle_lock.json").is_file():
                return candidate
    return None


def _sha256_file(path: Path) -> str:
    """Return lowercase hex SHA-256 digest of a file's raw bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PluginLoader:
    """Verifies Ed25519 signatures, SHA-256 manifest hashes, and AST safety before loading."""

    def __init__(
        self,
        trust_mode: PluginTrustMode = PluginTrustMode.DEV,
        trusted_public_keys: Optional[Sequence[bytes]] = None,
    ) -> None:
        self.trust_mode = trust_mode
        self.trusted_public_keys = list(trusted_public_keys or [])

    @staticmethod
    def compute_bundle_digest(adapter_path: Path, manifest_path: Path) -> bytes:
        """Compute canonical SHA-256 digest over manifest.toml + adapter.py."""
        h = hashlib.sha256()
        h.update(manifest_path.read_bytes())
        h.update(b"\x00")
        h.update(adapter_path.read_bytes())
        return h.digest()

    @staticmethod
    def _is_bundled_adapter(adapter_path: Path, manifest_path: Path) -> Optional[str]:
        """Return bundled tool name if paths resolve inside the first-party tools/ directory."""
        bundled_root = _find_bundled_tools_root()
        if bundled_root is None:
            return None
        resolved_root = bundled_root.resolve()
        adapter_resolved = adapter_path.resolve()
        manifest_resolved = manifest_path.resolve()
        if (
            adapter_resolved.parent == manifest_resolved.parent
            and adapter_resolved.parent.parent == resolved_root
            and adapter_resolved.name == "adapter.py"
            and manifest_resolved.name == "manifest.toml"
        ):
            return adapter_resolved.parent.name
        return None

    def _verify_bundled_adapter(
        self,
        tool_name: str,
        adapter_path: Path,
        manifest_path: Path,
        expected_manifest_sha256: Optional[str],
    ) -> None:
        """Verify first-party bundled adapter and manifest against tools/bundle_lock.json."""
        if expected_manifest_sha256 is not None:
            actual_manifest = _sha256_file(manifest_path)
            if actual_manifest.lower() != expected_manifest_sha256.lower():
                raise PluginSecurityError(
                    f"Manifest SHA-256 mismatch for '{manifest_path}': expected {expected_manifest_sha256}, got {actual_manifest}."
                )

        if self.trust_mode != PluginTrustMode.STRICT:
            return

        bundled_root = _find_bundled_tools_root()
        if bundled_root is None:
            raise PluginSecurityError(
                f"Bundled lockfile 'tools/bundle_lock.json' not found for '{tool_name}' in STRICT mode."
            )
        lock_path = bundled_root / "bundle_lock.json"
        try:
            lock_data: Dict[str, object] = json.loads(lock_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PluginSecurityError(
                f"Failed to read bundled lockfile '{lock_path}': {exc}"
            ) from exc

        adapters_map = lock_data.get("adapters")
        if not isinstance(adapters_map, dict) or tool_name not in adapters_map:
            raise PluginSecurityError(
                f"Bundled adapter '{tool_name}' is missing from '{lock_path}' in STRICT mode."
            )

        entry = adapters_map[tool_name]
        if not isinstance(entry, dict):
            raise PluginSecurityError(
                f"Invalid lockfile entry for bundled adapter '{tool_name}' in '{lock_path}'."
            )

        expected_m = str(entry.get("manifest_sha256", ""))
        expected_a = str(entry.get("adapter_sha256", ""))
        actual_m = _sha256_file(manifest_path)
        actual_a = _sha256_file(adapter_path)

        if not expected_m or actual_m.lower() != expected_m.lower():
            raise PluginSecurityError(
                f"Bundled manifest SHA-256 mismatch for '{tool_name}': expected {expected_m}, got {actual_m}."
            )
        if not expected_a or actual_a.lower() != expected_a.lower():
            raise PluginSecurityError(
                f"Bundled adapter SHA-256 mismatch for '{tool_name}': expected {expected_a}, got {actual_a}."
            )

    def _verify_signature(self, adapter_path: Path, manifest_path: Path) -> None:
        sig_path = adapter_path.with_suffix(".py.sig")
        if not sig_path.exists():
            if self.trust_mode == PluginTrustMode.STRICT:
                raise PluginSecurityError(
                    f"Missing Ed25519 signature '{sig_path}' in STRICT trust mode."
                )
            return

        if not self.trusted_public_keys:
            raise PluginSecurityError(
                "Signature present but no trusted Ed25519 public keys configured."
            )

        digest = self.compute_bundle_digest(adapter_path, manifest_path)
        sig_raw = base64.b64decode(sig_path.read_text(encoding="utf-8").strip().encode("ascii"))

        for pub_bytes in self.trusted_public_keys:
            try:
                Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_raw, digest)
                return
            except InvalidSignature:
                continue
        raise PluginSecurityError(f"Invalid Ed25519 signature for adapter '{adapter_path}'.")

    def _verify_manifest_hash(
        self, manifest_path: Path, expected_manifest_sha256: Optional[str]
    ) -> None:
        sha_path = manifest_path.with_suffix(".toml.sha256")
        expected = expected_manifest_sha256
        if expected is None and sha_path.exists():
            expected = sha_path.read_text(encoding="utf-8").strip().split()[0]
        if expected is None:
            if self.trust_mode == PluginTrustMode.STRICT:
                raise PluginSecurityError(
                    f"Missing manifest SHA-256 digest for '{manifest_path}' in STRICT mode."
                )
            return
        actual = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if actual.lower() != expected.lower():
            raise PluginSecurityError(
                f"Manifest SHA-256 mismatch for '{manifest_path}': expected {expected}, got {actual}."
            )

    def load_verified_adapter(
        self,
        adapter_path: Path,
        manifest_path: Path,
        expected_manifest_sha256: Optional[str] = None,
    ) -> ToolAdapter:
        """Verify manifest hash, signature or bundled lockfile, and AST safety, then instantiate ToolAdapter."""
        bundled_name = self._is_bundled_adapter(adapter_path, manifest_path)
        if bundled_name is not None:
            self._verify_bundled_adapter(
                bundled_name, adapter_path, manifest_path, expected_manifest_sha256
            )
        else:
            self._verify_manifest_hash(manifest_path, expected_manifest_sha256)
            self._verify_signature(adapter_path, manifest_path)

        source = adapter_path.read_text(encoding="utf-8")
        _check_adapter_ast(source, adapter_path)

        module_name = f"tools.{adapter_path.parent.name}.adapter"
        module = types.ModuleType(module_name)
        module.__file__ = str(adapter_path)
        code = compile(source, str(adapter_path), "exec")
        exec(code, module.__dict__)  # noqa: S102

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, ToolAdapter) and attr is not ToolAdapter:
                return attr()

        raise PluginSecurityError(f"No ToolAdapter subclass found in '{adapter_path}'.")
