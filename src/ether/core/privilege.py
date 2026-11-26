"""Least-privilege supervisor capability dropping and isolated scanner execution (ether.core.privilege)."""

from __future__ import annotations

import ctypes
import ctypes.util
import platform
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

# Linux prctl constants
_PR_SET_NO_NEW_PRIVS = 38
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_CLEAR_ALL = 4


class PrivilegeGovernor:
    """Enforces least-privilege execution by dropping supervisor capabilities on Linux."""

    @staticmethod
    def drop_supervisor_capabilities() -> Dict[str, Any]:
        """Set PR_SET_NO_NEW_PRIVS and clear ambient capabilities on Linux."""
        sys_name = platform.system().lower()
        if sys_name != "linux":
            return {"platform": sys_name, "supported": False, "no_new_privs": False}

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return {"platform": sys_name, "supported": False, "no_new_privs": False}

        libc = ctypes.CDLL(libc_name, use_errno=True)
        nnp_rc = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        amb_rc = libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        return {
            "platform": sys_name,
            "supported": True,
            "no_new_privs": nnp_rc == 0,
            "ambient_cleared": amb_rc == 0,
        }

    @staticmethod
    def build_isolated_worker_command(
        cmd: Sequence[str],
        uds_path: Optional[Path] = None,
        use_netns: bool = False,
    ) -> List[str]:
        """Wrap a scanner command in rootless netns / isolated worker invocation when available."""
        base_cmd = [str(c) for c in cmd]
        if uds_path is not None:
            return ["ether-worker", "--socket", str(uds_path), "--", *base_cmd]
        if use_netns and platform.system().lower() == "linux" and shutil.which("unshare"):
            return ["unshare", "--user", "--net", "--map-root-user", *base_cmd]
        return base_cmd
