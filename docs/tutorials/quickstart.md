# Quickstart Tutorial: Your First Ether Session

This tutorial guides you through your first programmatic session with Ether: initializing an in-memory or on-disk reactive graph, executing a security tool, and inspecting normalized telemetry.

---

## Prerequisites
- Python $\ge 3.11$
- Virtual environment with `ether` installed (`pip install -e .` or `pip install ether`)

---

## 1. Minimal Programmatic Session

Create a script `quickstart.py`:

```python
import asyncio
from ether import GraphStore, ToolRegistry, ActionGateway, GatePolicy
from ether.schemas.network import NetworkHost


async def main():
    print("[1] Initializing SQLite WAL GraphStore...")
    # Using :memory: for ephemeral runs or a path like "recon.db" for persistent storage
    store = GraphStore(":memory:")
    await store.initialize()

    print("[2] Creating Workspace and Investigation Session...")
    workspace_id = await store.create_workspace("Target Scope Alpha")
    session_id = await store.create_session(workspace_id, "External Surface Recon")
    print(f"    Session ID: {session_id}")

    print("[3] Discovering Pluggable Tool Adapters...")
    registry = ToolRegistry()
    registry.load_tools()
    print(f"    Loaded {len(registry.tools)} adapters: {list(registry.tools.keys())}")

    print("[4] Initializing ActionGateway with SAFE policy...")
    gateway = ActionGateway(registry, store, policy=GatePolicy.SAFE)
    print(f"    Active Policy: {gateway.policy}")

    print("[5] Injecting an initial discovered Entity (Host)...")
    host = NetworkHost.create(ip="192.168.1.50", hostname="gateway.internal")
    node_id = await store.upsert_finding(session_id, host)
    print(f"    Host Node ID: {node_id}")

    print("[6] Querying Graph for Active Entity Nodes...")
    node = await store.get_node(session_id, node_id)
    print(f"    Schema: {node['schema_type']}")
    print(f"    PIK:    {node['pik_json']}")

    print("[7] Closing Database Connections Cleanly...")
    await store.close()
    print("Done!")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## 2. Running the Script

```bash
python3 quickstart.py
```

### Expected Output:
```text
[1] Initializing SQLite WAL GraphStore...
[2] Creating Workspace and Investigation Session...
    Session ID: 4f3e2a1b-c8d9-4e5f-a6b7-8c9d0e1f2a3b
[3] Discovering Pluggable Tool Adapters...
    Loaded 11 adapters: ['dnspython', 'ffuf', 'gobuster', 'netexec', 'nikto', 'nmap', 'nuclei', 'searchsploit', 'sqlmap', 'subfinder', 'whois']
[4] Initializing ActionGateway with SAFE policy...
    Active Policy: GatePolicy.SAFE
[5] Injecting an initial discovered Entity (Host)...
    Host Node ID: 8a7c2e...
[6] Querying Graph for Active Entity Nodes...
    Schema: network.host
    PIK:    {"ip": "192.168.1.50"}
[7] Closing Database Connections Cleanly...
Done!
```

---

## Next Steps
- See [How to Author a Tool Adapter](../how-to/author-adapters.md) to add custom scanners.
- Read [Architecture Overview](../explanation/architecture.md) for deep module design principles.
