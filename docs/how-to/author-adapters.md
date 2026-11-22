# How to Author a Pluggable Tool Adapter

Ether adheres to the **"Smart Adapter / Simple Core"** invariant. The core engine is completely tool-agnostic; it understands only normalized Pydantic `BaseFinding` schemas, SQLite graph storage, process lifecycles, and pub/sub streams.

Adding or modifying a security tool is strictly additive: create a folder in `tools/<name>/` with a `manifest.toml` and `adapter.py`. Never edit core engine or database code to support a new tool.

---

## 1. Directory Structure

```text
tools/<tool_name>/
├── __init__.py
├── manifest.toml     # Discovery metadata, execution tier, input/output schemas
└── adapter.py        # Python class inheriting from ToolAdapter
```

---

## 2. Dual-Execution Protocol (Tier A vs Tier B)

Ether supports two execution tiers via a unified seam:

* **Tier A: In-Process Async Coroutine (`tier = "coroutine"`)**:
  Zero-fork, pure-async Python routines running directly inside the asyncio event loop (`http_probe`, `dnspython`). Extremely fast (<1ms latency), handles 10,000+ targets without process table exhaustion, and enforces SSRF/IMDS defenses.
* **Tier B: External Binary Subprocess (`tier = "binary"`)**:
  Spawns external compiled binaries (`nmap`, `nuclei`, `ffuf`, `subfinder`) via supervised argument vectors (`asyncio.create_subprocess_exec`) with 64KB disk spooling, environment secret scrubbing, and bounded ring buffers.

---

## 3. Defining `manifest.toml`

### Tier B Binary Adapter Manifest:
```toml
[meta]
name = "nmap"
description = "Network exploration tool and security / port scanner"
category = "Network"
categories = ["Network", "PortScan"]
binary = "nmap"
tier = "binary"

[modes]
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.host", "network.service"]
```

### Tier A In-Process Coroutine Manifest:
```toml
[meta]
name = "http_probe"
description = "Fast in-process HTTP/HTTPS probe with SSRF defense"
category = "Web Reconnaissance"
categories = ["web", "probe"]
tier = "coroutine"

[modes]
power = true

[input]
accepts = ["network.host", "network.service"]

[output]
produces = ["web.endpoint", "web.technology"]
```

---

## 4. Implementing `adapter.py`

### Option 1: Implementing a Tier B Subprocess Adapter
Subclass `ToolAdapter` and implement:
1. `validate_install()`: Check if binary exists on PATH.
2. `build_command()`: Return a safe argument vector (`List[str]`). **Zero `shell=True` allowed.**
3. `parse_output()`: Streamingly yield subclasses of `BaseFinding`.

```python
import shutil
from typing import Any, AsyncIterator, Dict, List, Optional
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.network import NetworkService


class NmapAdapter(ToolAdapter):
    def validate_install(self) -> bool:
        """Return True if the required binary is installed and executable."""
        return shutil.which("nmap") is not None

    def build_command(self, target: BaseFinding, params: Dict[str, Any]) -> List[str]:
        """Construct a safe argument vector from target and execution parameters."""
        ip = target.data.get("ip") or "127.0.0.1"
        flags = params.get("raw_flags", "-sV -T4").split()
        return ["nmap", *flags, ip]

    async def parse_output(
        self, line: str, target: BaseFinding, context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Parse incoming stdout line-by-line into normalized findings."""
        clean = line.strip()
        if "/tcp" in clean and "open" in clean:
            parts = clean.split()
            port_proto = parts[0].split("/")
            port = int(port_proto[0])
            protocol = port_proto[1]
            service = parts[2] if len(parts) > 2 else "unknown"

            yield NetworkService.create(
                host_ip=target.data.get("ip"),
                port=port,
                protocol=protocol,
                service_name=service,
            )
```

### Option 2: Implementing a Tier A Coroutine Adapter
Subclass `ToolAdapter` and implement `execute_coroutine()`:

```python
from typing import Any, AsyncIterator, Dict, Optional
import httpx
from ether.registry.adapter import ToolAdapter
from ether.schemas.base import BaseFinding
from ether.schemas.web import WebEndpoint


class HttpProbeAdapter(ToolAdapter):
    def validate_install(self) -> bool:
        """In-process coroutine adapters are always available."""
        return True

    async def execute_coroutine(
        self, target: BaseFinding, params: Dict[str, Any], context: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[BaseFinding]:
        """Execute async network probe directly within the event loop."""
        host = target.data.get("ip") or target.data.get("hostname")
        port = target.data.get("port", 80)
        url = f"http://{host}:{port}/"

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            try:
                resp = await client.get(url)
                yield WebEndpoint.create(
                    url=url,
                    status_code=resp.status_code,
                    title=self._extract_title(resp.text),
                    server=resp.headers.get("server"),
                )
            except Exception:
                pass
```

---

## 5. Automated Verification via Universal Fuzzing

Every tool adapter added to `tools/` is automatically discovered and subjected to universal adversarial testing in `tests/unit/test_parsers/test_fuzz_all_adapters.py`:
- Broken ANSI code explosions
- 20,000-token overflow strings
- Truncated JSON lines
- Embedded null bytes

Run the universal adapter test to verify your adapter:

```bash
pytest tests/unit/test_parsers/test_fuzz_all_adapters.py -k <tool_name>
```
