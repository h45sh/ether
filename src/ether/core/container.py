"""Deep module managing isolated, hermetic OCI container tool execution fallback."""

from __future__ import annotations

import os
import shutil
from typing import Dict, List, Optional


class ContainerizedToolRunner:
    """Supervisor for hermetic container tool execution fallback.

    Ensures zero host configuration when external security tool binaries are absent,
    while enforcing strict capability dropping and read-only host containment.
    """

    DEFAULT_IMAGE: str = "ghcr.io/ether/arsenal:0.1.3"

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if container tool fallback is explicitly enabled via environment or config."""
        val = os.environ.get("ETHER_CONTAINER_FALLBACK", "").strip().lower()
        return val in ("1", "true", "yes", "on")

    @classmethod
    def get_runtime(cls) -> Optional[str]:
        """Detect available OCI container runtime (podman preferred for rootless security, docker fallback)."""
        return shutil.which("podman") or shutil.which("docker")

    @classmethod
    def get_image(cls) -> str:
        """Return the pinned or configured container image reference."""
        return os.environ.get("ETHER_CONTAINER_IMAGE", cls.DEFAULT_IMAGE).strip()

    @classmethod
    def is_available(cls) -> bool:
        """Verify whether container tool fallback is both enabled and has a discoverable runtime."""
        return cls.is_enabled() and (cls.get_runtime() is not None)

    @classmethod
    def should_use_container(cls, binary_name: str, execution_tier: Optional[str] = None) -> bool:
        """Determine if a tool execution should fall back to containerized runner.

        Container fallback applies strictly to external binary adapters (Tier A/C).
        Never wraps in-process Python coroutines or explicit shell commands.
        """
        if execution_tier == "coroutine" or binary_name in (
            "sudo",
            "sh",
            "bash",
            "zsh",
            "stealth_scan",
        ):
            return False

        # If binary is installed locally on PATH, direct execution is preferred
        if shutil.which(binary_name):
            return False

        return cls.is_available()

    @classmethod
    def build_container_command(
        cls,
        command: List[str],
        cwd: str,
        env: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Construct a hardened, non-root OCI container execution argument vector.

        Invariants:
        - Pure argument vector (shell=False).
        - --rm: Container is destroyed immediately on termination.
        - --read-only: Root filesystem is immutable.
        - --cap-drop=ALL: All Linux capabilities dropped.
        - No host ~/.ether bind mount (forensic isolation).
        """
        runtime = cls.get_runtime()
        if not runtime:
            raise RuntimeError("No OCI container runtime (podman or docker) found on system PATH.")

        image = cls.get_image()

        container_cmd = [
            runtime,
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--network=host",
            "-w",
            cwd,
            "-v",
            f"{cwd}:{cwd}:rw",
        ]

        if env:
            from ether.core.executor import sanitize_subprocess_env

            cleaned_env = sanitize_subprocess_env(env)
            for k, v in cleaned_env.items():
                container_cmd.extend(["-e", f"{k}={v}"])

        container_cmd.append(image)
        container_cmd.extend(command)
        return container_cmd
