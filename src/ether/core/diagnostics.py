"""Environmental diagnostics and system integrity auditing for Ether.

Audits runtime prerequisites, database schema integrity, file descriptor limits,
spooler storage permissions, and security tool binary discovery across Debian, Arch,
Fedora, and macOS.
"""

import asyncio
import os
import platform
import resource
import shutil
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

from ether import paths
from ether.common.logging import get_recent_crash_summary
from ether.graph.store import GraphStore
from ether.registry.registry import ToolRegistry

INSTALLATION_HINTS: Dict[str, str] = {
    "nmap": "sudo apt install nmap  (or: pacman -S nmap / brew install nmap)",
    "gobuster": "sudo apt install gobuster  (or: go install github.com/OJ/gobuster/v3@latest)",
    "nikto": "sudo apt install nikto  (or: pacman -S nikto / brew install nikto)",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "whois": "sudo apt install whois  (or: pacman -S whois / brew install whois)",
    "dnspython": "pip install dnspython",
    "ffuf": "sudo apt install ffuf  (or: go install github.com/ffuf/ffuf/v2@latest)",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "searchsploit": "sudo apt install exploitdb  (or: pacman -S exploitdb)",
    "sqlmap": "sudo apt install sqlmap  (or: pacman -S sqlmap / brew install sqlmap)",
    "netexec": "pipx install netexec  (or: sudo apt install netexec)",
    "nxc": "pipx install netexec  (or: sudo apt install netexec)",
}


@dataclass
class DiagnosticCheck:
    name: str
    category: str
    status: str  # "ok", "warning", "error", "info"
    message: str
    remedy: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class DiagnosticReport:
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    system_info: Dict[str, Any] = field(default_factory=dict)
    checks: List[DiagnosticCheck] = field(default_factory=list)
    healthy: bool = True
    tool_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "system_info": self.system_info,
            "healthy": self.healthy,
            "tool_counts": self.tool_counts,
            "checks": [asdict(c) for c in self.checks],
        }

    def summary(self) -> Dict[str, int]:
        counts = {"ok": 0, "warning": 0, "error": 0, "info": 0}
        for c in self.checks:
            counts[c.status] = counts.get(c.status, 0) + 1
        return counts


class DiagnosticEngine:
    """Deep module managing environmental health auditing and system verification."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        tools_dir: Optional[str] = None,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        self.db_path = db_path or paths.get_default_db_path()
        self.tools_dir = tools_dir
        self.registry = registry or ToolRegistry(self.tools_dir)
        if not self.registry.list_tools():
            try:
                self.registry.load_tools()
            except Exception:
                pass

    async def run(self) -> DiagnosticReport:
        """Run complete diagnostic audit and return structured report."""
        report = DiagnosticReport()
        self._check_system(report)
        self._check_logs(report)
        self._check_tools(report)
        await self._check_database(report)
        return report

    def _check_system(self, report: DiagnosticReport) -> None:
        """Evaluate Python runtime, platform, and process resource limits."""
        py_version = sys.version_info
        py_version_str = f"{py_version.major}.{py_version.minor}.{py_version.micro}"

        # Resource limits: file descriptors
        soft_fd, hard_fd = 1024, 4096
        try:
            soft_fd, hard_fd = resource.getrlimit(resource.RLIMIT_NOFILE)
        except Exception:
            pass

        report.system_info = {
            "python_version": py_version_str,
            "platform": platform.platform(),
            "executable": sys.executable,
            "max_file_descriptors": {"soft": soft_fd, "hard": hard_fd},
        }

        # 1. Python runtime check
        if py_version >= (3, 11):
            report.checks.append(
                DiagnosticCheck(
                    name="Python Runtime",
                    category="System",
                    status="ok",
                    message=f"Python {py_version_str} (>= 3.11 requirement satisfied)",
                )
            )
        else:
            report.checks.append(
                DiagnosticCheck(
                    name="Python Runtime",
                    category="System",
                    status="error",
                    message=f"Python {py_version_str} is below minimum requirement 3.11",
                    remedy="Upgrade Python to 3.11 or newer",
                )
            )
            report.healthy = False

        # 2. File descriptor headroom
        if soft_fd >= 1024:
            report.checks.append(
                DiagnosticCheck(
                    name="File Descriptor Limits",
                    category="System",
                    status="ok",
                    message=f"Soft limit: {soft_fd}, Hard limit: {hard_fd}",
                )
            )
        else:
            report.checks.append(
                DiagnosticCheck(
                    name="File Descriptor Limits",
                    category="System",
                    status="warning",
                    message=f"Soft limit ({soft_fd}) is low for high-concurrency port scanning",
                    remedy="Increase file descriptor limits: ulimit -n 4096",
                )
            )

    def _check_logs(self, report: DiagnosticReport) -> None:
        """Verify centralized system logging directory and check for recent fatal crashes."""
        data_dir = (
            os.path.dirname(os.path.abspath(self.db_path)) if self.db_path != ":memory:" else None
        )
        logs_dir = paths.get_default_logs_dir(data_dir)
        log_file = paths.get_system_log_path(data_dir)

        is_writable = False
        try:
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir, exist_ok=True)
            is_writable = os.access(logs_dir, os.W_OK)
        except Exception:
            is_writable = False

        if is_writable:
            report.checks.append(
                DiagnosticCheck(
                    name="Diagnostic Logs Directory",
                    category="Logging",
                    status="ok",
                    message=f"Logs directory '{logs_dir}' is writable",
                )
            )
        else:
            report.checks.append(
                DiagnosticCheck(
                    name="Diagnostic Logs Directory",
                    category="Logging",
                    status="warning",
                    message=f"Logs directory '{logs_dir}' is not writable",
                    remedy=f"Grant write permissions: chmod 700 {logs_dir}",
                )
            )

        crash = get_recent_crash_summary(data_dir)
        if crash:
            report.checks.append(
                DiagnosticCheck(
                    name="Recent Crash Audit",
                    category="Logging",
                    status="warning",
                    message=f"Recent crash recorded [{crash['timestamp']}]: {crash['summary']}",
                    details=crash,
                    remedy="Inspect crash trace in system.log",
                )
            )
        else:
            report.checks.append(
                DiagnosticCheck(
                    name="Recent Crash Audit",
                    category="Logging",
                    status="ok",
                    message=f"No unhandled crashes recorded in log ({log_file})",
                )
            )

    async def _check_database(self, report: DiagnosticReport) -> None:
        """Verify database directory permissions, SQLite schema integrity, and WAL mode."""
        db_dir = (
            os.path.dirname(os.path.abspath(self.db_path)) if self.db_path != ":memory:" else None
        )
        if db_dir:
            try:
                os.makedirs(db_dir, exist_ok=True)
                is_writable = os.access(db_dir, os.W_OK)
            except Exception:
                is_writable = False

            if is_writable:
                report.checks.append(
                    DiagnosticCheck(
                        name="Storage Directory",
                        category="Database",
                        status="ok",
                        message=f"Directory '{db_dir}' is writable",
                    )
                )
            else:
                report.checks.append(
                    DiagnosticCheck(
                        name="Storage Directory",
                        category="Database",
                        status="error",
                        message=f"Directory '{db_dir}' is not writable",
                        remedy=f"Grant write permissions: chmod 700 {db_dir}",
                    )
                )
                report.healthy = False

        store = GraphStore(self.db_path)
        try:
            await store.initialize()
            integrity_status, tables = await store.check_integrity()
            if integrity_status == "ok":
                report.checks.append(
                    DiagnosticCheck(
                        name="SQLite Integrity",
                        category="Database",
                        status="ok",
                        message=f"Database '{self.db_path}' verified ({len(tables)} tables present)",
                        details={"tables": tables},
                    )
                )
            else:
                report.checks.append(
                    DiagnosticCheck(
                        name="SQLite Integrity",
                        category="Database",
                        status="error",
                        message=f"Database integrity check failed: {integrity_status}",
                        remedy="Rebuild or repair SQLite database",
                    )
                )
                report.healthy = False
        except Exception as e:
            report.checks.append(
                DiagnosticCheck(
                    name="SQLite Database",
                    category="Database",
                    status="error",
                    message=f"Failed to initialize database: {e}",
                    remedy=f"Check permissions and path for '{self.db_path}'",
                )
            )
            report.healthy = False
        finally:
            await store.close()

    def _check_tools(self, report: DiagnosticReport) -> None:
        """Check discovery and binary availability for all registered security tool adapters."""
        available_count = 0
        missing_count = 0

        for tool_name in self.registry.list_tools():
            tool_data = self.registry.get_tool(tool_name)
            binary_name = tool_name
            if tool_data and "manifest" in tool_data:
                binary_name = getattr(tool_data["manifest"], "binary", tool_name)

            bin_path = shutil.which(binary_name)
            if bin_path:
                available_count += 1
                report.checks.append(
                    DiagnosticCheck(
                        name=f"Tool: {tool_name}",
                        category="Tools",
                        status="ok",
                        message=f"Binary '{binary_name}' found at {bin_path}",
                        details={"path": bin_path, "tool": tool_name},
                    )
                )
            else:
                missing_count += 1
                remedy = INSTALLATION_HINTS.get(tool_name, f"Install '{tool_name}' on host system")
                report.checks.append(
                    DiagnosticCheck(
                        name=f"Tool: {tool_name}",
                        category="Tools",
                        status="info",
                        message=f"Binary '{binary_name}' is not installed",
                        remedy=remedy,
                        details={"tool": tool_name},
                    )
                )

        report.tool_counts = {
            "available": available_count,
            "missing": missing_count,
            "total": available_count + missing_count,
        }

    @staticmethod
    def format_terminal_report(report: DiagnosticReport) -> str:
        """Format the diagnostic report for terminal display."""
        lines = []
        lines.append("=" * 60)
        lines.append("Ether System & Environmental Diagnostic Report")
        lines.append("=" * 60)
        lines.append(f"Timestamp:  {report.timestamp}")
        lines.append(f"Python:     {report.system_info.get('python_version', 'Unknown')}")
        lines.append(f"Platform:   {report.system_info.get('platform', 'Unknown')}")
        lines.append(
            f"Tools:      {report.tool_counts.get('available', 0)} installed, {report.tool_counts.get('missing', 0)} missing"
        )
        lines.append("-" * 60)

        current_category = None
        for check in report.checks:
            if check.category != current_category:
                current_category = check.category
                lines.append(f"\n[{current_category}]")

            status_tag = f"[{check.status.upper()}]"
            lines.append(f"  {status_tag:<9} {check.name}: {check.message}")
            if check.remedy:
                lines.append(f"            Remedy: {check.remedy}")

        lines.append("-" * 60)
        summary = report.summary()
        status_line = (
            f"Result: {'HEALTHY' if report.healthy else 'UNHEALTHY'} "
            f"({summary.get('ok', 0)} passed, {summary.get('warning', 0)} warnings, {summary.get('error', 0)} errors)"
        )
        lines.append(status_line)
        lines.append("=" * 60)
        return "\n".join(lines)

    async def collect_runtime_metrics(self) -> Dict[str, Any]:
        """Collect real-time substrate telemetry metrics with zero external dependencies."""
        soft_fd, hard_fd = 1024, 4096
        try:
            soft_fd, hard_fd = resource.getrlimit(resource.RLIMIT_NOFILE)
        except Exception:
            pass

        open_fds = -1
        try:
            if os.path.exists("/proc/self/fd"):
                open_fds = len(os.listdir("/proc/self/fd"))
        except Exception:
            open_fds = -1

        rss_bytes = -1
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            if platform.system() == "Darwin":
                rss_bytes = int(usage.ru_maxrss)
            else:
                rss_bytes = int(usage.ru_maxrss * 1024)
        except Exception:
            rss_bytes = -1

        loop_lag = 0.0
        try:
            loop = asyncio.get_running_loop()
            t0 = loop.time()
            await asyncio.sleep(0)
            loop_lag = max(0.0, loop.time() - t0)
        except Exception:
            loop_lag = 0.0

        return {
            "open_fds": open_fds,
            "max_fds": {"soft": soft_fd, "hard": hard_fd},
            "resident_memory_bytes": rss_bytes,
            "event_loop_lag_seconds": loop_lag,
            "active_workers": 0,
            "queue_depth": 0,
            "subprocess_latencies": {"p50": 0.0, "p90": 0.0, "p99": 0.0},
        }

    def to_prometheus_text(self, metrics: Optional[Dict[str, Any]] = None) -> str:
        """Format metrics into standard Prometheus text format (text/plain; version=0.0.4)."""
        if metrics is None:
            soft_fd, hard_fd = 1024, 4096
            try:
                soft_fd, hard_fd = resource.getrlimit(resource.RLIMIT_NOFILE)
            except Exception:
                pass
            open_fds = -1
            try:
                if os.path.exists("/proc/self/fd"):
                    open_fds = len(os.listdir("/proc/self/fd"))
            except Exception:
                pass
            rss_bytes = -1
            try:
                usage = resource.getrusage(resource.RUSAGE_SELF)
                rss_bytes = (
                    int(usage.ru_maxrss)
                    if platform.system() == "Darwin"
                    else int(usage.ru_maxrss * 1024)
                )
            except Exception:
                pass

            metrics = {
                "open_fds": open_fds,
                "max_fds": {"soft": soft_fd, "hard": hard_fd},
                "resident_memory_bytes": rss_bytes,
                "event_loop_lag_seconds": 0.0,
                "active_workers": 0,
                "queue_depth": 0,
                "subprocess_latencies": {"p50": 0.0, "p90": 0.0, "p99": 0.0},
            }

        lines = [
            "# HELP ether_process_open_fds Number of open file descriptors in current process",
            "# TYPE ether_process_open_fds gauge",
            f"ether_process_open_fds {metrics.get('open_fds', 0)}",
            "# HELP ether_process_max_fds Soft limit of max open file descriptors",
            "# TYPE ether_process_max_fds gauge",
            f"ether_process_max_fds {metrics.get('max_fds', {}).get('soft', 1024)}",
            "# HELP ether_process_resident_memory_bytes Resident set size in bytes",
            "# TYPE ether_process_resident_memory_bytes gauge",
            f"ether_process_resident_memory_bytes {metrics.get('resident_memory_bytes', 0)}",
            "# HELP ether_event_loop_lag_seconds Asyncio event loop latency in seconds",
            "# TYPE ether_event_loop_lag_seconds gauge",
            f"ether_event_loop_lag_seconds {metrics.get('event_loop_lag_seconds', 0.0):.6f}",
            "# HELP ether_active_workers Number of active worker coroutines",
            "# TYPE ether_active_workers gauge",
            f"ether_active_workers {metrics.get('active_workers', 0)}",
            "# HELP ether_queue_depth Pending queue depth across execution pipelines",
            "# TYPE ether_queue_depth gauge",
            f"ether_queue_depth {metrics.get('queue_depth', 0)}",
            "# HELP ether_subprocess_duration_seconds Subprocess execution latency percentiles",
            "# TYPE ether_subprocess_duration_seconds summary",
        ]
        latencies = metrics.get("subprocess_latencies", {})
        lines.append(
            f'ether_subprocess_duration_seconds{{quantile="0.5"}} {latencies.get("p50", 0.0)}'
        )
        lines.append(
            f'ether_subprocess_duration_seconds{{quantile="0.9"}} {latencies.get("p90", 0.0)}'
        )
        lines.append(
            f'ether_subprocess_duration_seconds{{quantile="0.99"}} {latencies.get("p99", 0.0)}'
        )
        return "\n".join(lines) + "\n"
