"""Centralized path resolution and data directory management for Ether."""

import os
from typing import Optional

ENV_DATA_DIR = "ETHER_DATA_DIR"
DEFAULT_DATA_DIR_NAME = ".ether"


def get_default_data_dir() -> str:
    """Return the absolute path to the Ether unified data directory.

    Priority:
    1. ETHER_DATA_DIR environment variable
    2. ~/.ether directory in user's home folder
    """
    env_dir = os.environ.get(ENV_DATA_DIR)
    if env_dir:
        base_dir = os.path.abspath(os.path.expanduser(env_dir))
    else:
        base_dir = os.path.abspath(os.path.expanduser(f"~/{DEFAULT_DATA_DIR_NAME}"))

    try:
        os.makedirs(base_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return base_dir


def get_default_db_path(data_dir: Optional[str] = None) -> str:
    """Return the default SQLite database path."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    return os.path.join(base, "ether.db")


def get_default_settings_path(data_dir: Optional[str] = None) -> str:
    """Return the default settings.json path."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    return os.path.join(base, "settings.json")


def get_default_scratchpad_path(data_dir: Optional[str] = None) -> str:
    """Return the default scratchpad markdown file path."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    return os.path.join(base, "scratchpad.md")


def get_default_checkpoints_dir(data_dir: Optional[str] = None) -> str:
    """Return the default learning mode checkpoint export directory."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    checkpoints_dir = os.path.join(base, "checkpoints")
    try:
        os.makedirs(checkpoints_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return checkpoints_dir


def get_default_exports_dir(data_dir: Optional[str] = None) -> str:
    """Return the default session database export directory."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    exports_dir = os.path.join(base, "exports")
    try:
        os.makedirs(exports_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return exports_dir


def get_default_reports_dir(data_dir: Optional[str] = None) -> str:
    """Return the default session markdown report export directory."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    reports_dir = os.path.join(base, "reports")
    try:
        os.makedirs(reports_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return reports_dir


def get_default_logs_dir(data_dir: Optional[str] = None) -> str:
    """Return the default action execution logs directory."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    logs_dir = os.path.join(base, "logs")
    try:
        os.makedirs(logs_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return logs_dir


def get_action_log_path(action_id: str, data_dir: Optional[str] = None) -> str:
    """Return the absolute path for an action execution log file."""
    logs_dir = get_default_logs_dir(data_dir)
    return os.path.join(logs_dir, f"{action_id}.log")


def get_system_log_path(data_dir: Optional[str] = None) -> str:
    """Return the absolute path for the centralized application system log (~/.ether/logs/ether.log)."""
    logs_dir = get_default_logs_dir(data_dir)
    return os.path.join(logs_dir, "ether.log")


def get_default_wordlists_dir(data_dir: Optional[str] = None) -> str:
    """Return the default wordlists directory (~/.ether/wordlists)."""
    base = data_dir if data_dir is not None else get_default_data_dir()
    wordlists_dir = os.path.join(base, "wordlists")
    try:
        os.makedirs(wordlists_dir, mode=0o700, exist_ok=True)
    except OSError:
        pass
    return wordlists_dir


def get_wordlist_path(name: str, data_dir: Optional[str] = None) -> str:
    """Return the absolute path for a named wordlist in the wordlists directory."""
    wordlists_dir = get_default_wordlists_dir(data_dir)
    filename = name if name.endswith(".txt") else f"{name}.txt"
    return os.path.join(wordlists_dir, filename)


def get_git_branch(target_dir: Optional[str] = None) -> str:
    """Resolve the active git branch purely from filesystem metadata without spawning child subprocesses."""
    cur = os.path.abspath(target_dir or os.getcwd())
    while True:
        git_candidate = os.path.join(cur, ".git")
        if os.path.isdir(git_candidate):
            head_path = os.path.join(git_candidate, "HEAD")
            try:
                with open(head_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.startswith("ref: refs/heads/"):
                        return content.split("ref: refs/heads/", 1)[1].strip()
                    elif content:
                        # Detached HEAD - return short SHA
                        return content[:7]
            except Exception:
                return ""
        elif os.path.isfile(git_candidate):
            # Git worktree or submodule reference: "gitdir: /path/to/.git/worktrees/name"
            try:
                with open(git_candidate, "r", encoding="utf-8") as f:
                    line = f.readline().strip()
                    if line.startswith("gitdir:"):
                        git_dir = line.split("gitdir:", 1)[1].strip()
                        if not os.path.isabs(git_dir):
                            git_dir = os.path.abspath(os.path.join(cur, git_dir))
                        head_path = os.path.join(git_dir, "HEAD")
                        if os.path.exists(head_path):
                            with open(head_path, "r", encoding="utf-8") as hf:
                                content = hf.read().strip()
                                if content.startswith("ref: refs/heads/"):
                                    return content.split("ref: refs/heads/", 1)[1].strip()
                                elif content:
                                    return content[:7]
            except Exception:
                return ""
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return ""


def atomic_create_file(path: str, content: str = "") -> None:
    """Atomically create a private file with mode 0o600 (-rw-------) preventing TOCTOU vulnerabilities."""
    base_dir = os.path.dirname(os.path.abspath(path))
    if base_dir:
        os.makedirs(base_dir, mode=0o700, exist_ok=True)
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        if content:
            os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
