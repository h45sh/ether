# Quickstart Tutorial: Your First End-to-End Ether Session

Welcome to Ether! This tutorial is a hands-on, step-by-step lesson designed to guide you through your very first interactive session with the engine.

By the end of this 10-minute tutorial, you will know how to:
1. Verify system readiness and security tool discovery using `ether doctor`.
2. Create an isolated investigation session in the SQLite WAL graph.
3. Supervise and execute a reconnaissance scan.
4. Inspect discovered entities and run offline semantic vector search.
5. Extract token-budgeted AI agent telemetry and zero-token diffs.
6. Export a password-protected, encrypted forensic archive.

---

## Prerequisites

Before beginning, ensure you have:
* Python $\ge 3.11$ installed.
* Ether installed in an active virtual environment:
  ```bash
  cd ether
  source .venv/bin/activate
  ```

---

## Step 1: Verify System Readiness (`ether doctor`)

Ether operates as a headless kernel supervising underlying security tools. First, verify that your environment, database, vector extensions, and tool adapters are healthy:

```bash
ether doctor
```

### Expected Output:
```text
============================================================
              Ether System Diagnostic Report                
============================================================
Platform: Linux (x86_64) | Python: 3.12.x
Database: /home/user/.ether/ether.db (SQLite 3.45+, WAL Mode)
sqlite-vec Extension: LOADABLE (vec0 virtual table enabled)
Security Policy: GatePolicy.SAFE (SSRF & IMDS defense active)

Discovered Pluggable Tool Adapters (12 available):
  [+] nmap             -> /usr/bin/nmap
  [+] nuclei           -> /usr/local/bin/nuclei
  [+] ffuf             -> /usr/bin/ffuf
  [+] gobuster         -> /usr/bin/gobuster
  [+] subfinder        -> /usr/local/bin/subfinder
  [+] nikto            -> /usr/local/bin/nikto
  [+] searchsploit     -> /usr/local/bin/searchsploit
  [+] sqlmap           -> /usr/bin/sqlmap
  [+] whois            -> /usr/bin/whois
  [+] dnspython        -> Python in-process coroutine (Tier A)
  [+] http_probe       -> Python in-process coroutine (Tier A)

Overall Health: [HEALTHY] All systems operational.
============================================================
```

> [!NOTE]
> If any binary tools show as `MISSING`, you can still complete this tutorial! Ether includes native in-process coroutine adapters (`http_probe`, `dnspython`) that execute directly in Python with zero external binary dependencies.

---

## Step 2: Create an Investigation Workspace & Session

All findings discovered by Ether are partitioned into **Workspaces** (engagements or targets) and **Sessions** (specific phases or actions).

Create a new session for your target:

```bash
ether session create "Tutorial Recon Engagement"
```

### Expected Output:
```text
[+] Created Session: Tutorial Recon Engagement
    Session ID: a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d
    Workspace:  Default Workspace
    Status:     ACTIVE
```

Save the generated `Session ID` (e.g. `a1b2c3d4-...`), as we will use it in subsequent commands. For convenience in your terminal, export it as an environment variable:

```bash
export SESSION="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
```

---

## Step 3: Supervise a Reconnaissance Scan (`ether run`)

Now, let's run our first scan under Ether's reactive supervisor. We'll use the native in-process `http_probe` adapter against a test domain:

```bash
ether run http_probe https://scanme.nmap.org --session-id "$SESSION"
```

### What Ether does behind the scenes:
1. **Pre-Flight Validation:** `ActionGateway` verifies the target against `GatePolicy.SAFE` (blocking AWS/GCP cloud metadata IP `169.254.169.254` and link-local ranges).
2. **Supervised Execution:** Streams HTTP response headers, status codes, and TLS certificates without spawning unconstrained subshells.
3. **Pydantic Normalization:** Parses streaming responses into normalized `WebEndpoint` and `WebTechnology` schemas.
4. **Deterministic Upsert:** Calculates SHA-256 Primary Identity Keys (PIKs) and inserts nodes into SQLite WAL storage.

### Expected Output:
```text
[*] [Action: 8f9e0a1b] Executing tool 'http_probe' against 'https://scanme.nmap.org'
[*] Policy: SAFE | Execution Tier: In-Process Coroutine
[+] [http_probe] Discovered endpoint: https://scanme.nmap.org (Status: 200, Content-Length: 182)
[+] [http_probe] Server Header: Apache/2.4.7 (Ubuntu)
[+] [http_probe] Favicon Hash (SHA-256): 9b4d...

--- Action Execution Summary ---
Action ID:        8f9e0a1b-3c4d-5e6f-7a8b-9c0d1e2f3a4b
Status:           COMPLETED
Duration:         0.42s
Findings Ingested: 2 nodes, 1 edge
```

---

## Step 4: Inspect the Discovered Entity Graph (`ether graph`)

Unlike traditional scanners that leave you with disparate text files, Ether integrates all findings into a unified relational graph.

### List all active nodes in the session:
```bash
ether graph list-nodes "$SESSION"
```

### Expected Output:
```text
========================================================================================
                      Discovered Entities for Session: Tutorial Recon
========================================================================================
Node ID       Schema Type         Status     Last Seen            Summary
----------------------------------------------------------------------------------------
7a8f9c0d...   web.endpoint        confirmed  2026-11-22 17:30:12  https://scanme.nmap.org [200]
3e4f5a6b...   web.technology      confirmed  2026-11-22 17:30:12  Apache/2.4.7 (web_server)
========================================================================================
Total Entities: 2 active nodes (0 flapping, 0 stale)
```

---

## Step 5: Perform Offline Semantic Vector Search (`sqlite-vec`)

Ether embeds discovered finding attributes into 384-dimensional unit vectors stored in a `vec0` virtual table. You can query your attack surface using natural language without making any external API calls:

```bash
ether graph search "$SESSION" "Apache web server and open HTTP endpoints"
```

### Expected Output:
```text
========================================================================================
            Semantic Search Results for: 'Apache web server and open HTTP endpoints'
========================================================================================
Rank  Distance  Schema Type      Node ID       Summary
----------------------------------------------------------------------------------------
1     0.1824    web.technology   3e4f5a6b...   Apache/2.4.7 (web_server) on https://scanme.nmap.org
2     0.2410    web.endpoint     7a8f9c0d...   https://scanme.nmap.org [200 OK] (182 bytes)
========================================================================================
```

---

## Step 6: Extract AI Telemetry & Zero-Token Diffs (`ether telemetry`)

When AI agents interact with security tools, sending raw console logs consumes tens of thousands of tokens. Ether provides two zero-waste abstractions:

### A. Extract a Token-Budgeted State Snapshot:
```bash
ether telemetry snapshot "$SESSION" --budget 1000
```
Ether uses a knapsack budgeting algorithm to pack the highest-priority graph findings into a compact JSON telemetry envelope under your exact token budget.

### B. Extract a Zero-Token Set-Theoretic Delta:
```bash
ether telemetry diff "$SESSION"
```
Returns only what changed since the baseline timestamp ($\Delta = S_{t+1} \setminus S_t$), eliminating 98% of redundant LLM context usage!

---

## Step 7: Export an Encrypted Forensic Session Archive

When your investigation is complete, export the session into a password-protected, cryptographically authenticated archive:

```bash
ether graph export "$SESSION" -o engagement_backup.enc --encrypt --passphrase "SuperSecretPassphrase123"
```

### Expected Output:
```text
[+] Successfully exported session 'Tutorial Recon Engagement'
    Destination: engagement_backup.enc
    Encryption:  AES-256-GCM (Argon2id key derivation)
    Nodes:       2
    Events:      1 action audit events
```

You can import this archive on any machine running Ether with:
```bash
ether graph import engagement_backup.enc --passphrase "SuperSecretPassphrase123"
```

---

## Step 8: Taking It Programmatic (Python SDK)

Everything you just completed via the CLI can also be executed in Python using Ether's deep module SDK:

```python
import asyncio
from ether import ActionGateway, GatePolicy, GraphStore, ToolRegistry
from ether.schemas.web import WebEndpoint


async def run_programmatic():
    store = GraphStore(":memory:")
    await store.initialize()

    ws_id = await store.create_workspace("SDK Workspace")
    sess_id = await store.create_session(ws_id, "SDK Session")

    # Ingest a finding programmatically
    endpoint = WebEndpoint.create(
        url="https://api.internal.corp/v1/health", status_code=200, content_length=42
    )
    node_id = await store.upsert_finding(sess_id, endpoint)
    print(f"[+] Upserted Finding Node: {node_id}")

    # Semantic Vector Search
    hits = await store.semantic_search(sess_id, "health check API", limit=1)
    print(f"[+] Top Semantic Match: {hits[0]['data']['url']}")

    await store.close()


if __name__ == "__main__":
    asyncio.run(run_programmatic())
```

---

## Tutorial Complete! What’s Next?

Congratulations! You have mastered the fundamentals of Ether. Here is where to explore next depending on your goals:

- **Connect Your AI Agent (Claude Desktop / Cursor):** Follow the [Agent Telemetry & MCP Guide](../how-to/agent-telemetry-mcp.md).
- **Master the Full CLI Command Set:** Consult the [Headless CLI Operations Manual](../how-to/cli-usage.md).
- **Build a Custom Security Tool Adapter:** Read [Authoring Pluggable Tool Adapters](../how-to/author-adapters.md).
- **Understand the Architecture & Invariants:** Read the [Architecture Deep Dive](../explanation/architecture.md).
