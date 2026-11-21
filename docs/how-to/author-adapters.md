# How to Author a Pluggable Tool Adapter

Ether adheres to the **"Smart Adapter / Simple Core"** invariant. The core engine is completely tool-agnostic; it understands only normalized Pydantic `BaseFinding` schemas, SQLite graph storage, process lifecycles, and pub/sub streams.

Adding or modifying a security tool is strictly additive: create a folder in `tools/<name>/` with a `manifest.toml` and `adapter.py`. Never edit core engine or database code to support a new tool.

---

## 1. Directory Structure

```
tools/<tool_name>/
 manifest.toml # Discovery metadata, binary, input/output schemas
 adapter.py # Python class inheriting from ToolAdapter
```

---

## 2. Step 1: Define `manifest.toml`

The manifest registers your tool with Ether's dynamic registry:

```toml
[meta]
name = "nmap"
description = "Network exploration tool and security / port scanner"
category = "Network"
categories = ["Network", "PortScan"]
binary = "nmap"

[modes]
power = true

[input]
accepts = ["network.host"]

[output]
produces = ["network.host", "network.service"]
```

---

## 3. Step 2: Implement `adapter.py`

Subclass `ToolAdapter` and implement the three required methods:
1. `validate_install()`: Check if binary exists.
2. `build_command()`: Return a safe argument vector (`List[str]`). **Zero `shell=True` allowed.**
3. `parse_output()`: Streamingly yield subclasses of `BaseFinding`.

```python
import shutil
from typing import Any, AsyncIterator, Dict, List
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
 service=service,
 )
```

---

## 4. Step 3: Mechanical Verification via Fuzzing

All tool adapters are automatically subjected to adversarial streams (broken ANSI codes, 20,000-token lines, truncated JSON, and null bytes).

Run the universal adapter test to verify your adapter:

```bash
pytest tests/unit/test_parsers/test_fuzz_all_adapters.py -k nmap
```

If it survives without crashing or hanging, your adapter is ready for production.
