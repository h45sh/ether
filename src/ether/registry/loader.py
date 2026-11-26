"""Cryptographic plugin attestation and AST-sandboxed adapter loader (ether.registry.loader)."""

from __future__ import annotations

import ast
import base64
import hashlib
import types
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

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

    def _verify_signature(self, adapter_path: Path, manifest_path: Path) -> None:
        sig_path = adapter_path.with_suffix(".py.sig")
        if not sig_path.exists():
            if self.trust_mode == PluginTrustMode.STRICT:
                raise PluginSecurityError(
                    f"Missing Ed25519 signature '{sig_path}' in STRICT trust mode."
                )
            return

        if not self.trusted_public_keys:
            raise PluginSecurityError("Signature present but no trusted Ed25519 public keys configured.")

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
        """Verify manifest hash, Ed25519 signature, and AST safety, then instantiate ToolAdapter."""
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
            if (
                isinstance(attr, type)
                and issubclass(attr, ToolAdapter)
                and attr is not ToolAdapter
            ):
                return attr()

        raise PluginSecurityError(f"No ToolAdapter subclass found in '{adapter_path}'.")
