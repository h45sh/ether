<div align="center">

# ETHER

**The Reactive Telemetry & Process Supervisor Substrate for Cybersecurity Tooling & Autonomous AI Agents**

[PyPI](https://pypi.org/project/ether-core/) · [Documentation Hub](https://github.com/h45sh/ether/blob/main/docs/README.md) · [Roadmap](https://github.com/h45sh/ether/blob/main/ROADMAP.md) · [Contributing](https://github.com/h45sh/ether/blob/main/docs/CONTRIBUTING.md) · [Security Policy](https://github.com/h45sh/ether/blob/main/docs/SECURITY.md)

[![CodeQL Security Analysis](https://github.com/h45sh/ether/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/h45sh/ether/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/ether-core.svg)](https://pypi.org/project/ether-core/)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://github.com/h45sh/ether/pkgs/container/ether)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Architecture: Headless Core](https://img.shields.io/badge/architecture-headless%20core-success)](https://github.com/h45sh/ether/blob/main/docs/explanation/architecture.md)

*Ether operates as a deterministic process supervisor and reactive telemetry engine for cybersecurity operations—supervising CLI processes, normalizing streaming stdout/stderr into typed findings, and maintaining a live, event-sourced entity graph without UI bloat.*

</div>

---

## What is Ether?

Security tools like `nmap`, `nuclei`, `ffuf`, and `gobuster` are essential, but orchestrating them in modern workflows or autonomous AI agent loops is notoriously fragile:
- **Unstructured Terminal Noise:** Tools spew tens of thousands of lines of terminal ANSI garbage. Parsing stdout line-by-line in ad-hoc bash scripts breaks easily.
- **LLM Context Window Exhaustion:** AI agents executing raw bash subshells burn through 50,000+ tokens per scan, lose state across commands, and suffer from hallucinations.
- **No Unified World State:** Discovered entities (hosts, ports, URLs, CVEs) are trapped in disparate text files without a shared relational model.
- **Prompt Injection Risks:** Raw scanner output from untrusted targets can contain prompt injection attacks targeting LLM agents.

**Ether solves this at the substrate level.** It acts as an execution supervisor and telemetry compiler that sits between cybersecurity tools and userland applications (AI agents, CLI operators, and security automation pipelines).

---

## The Supervisory Architecture for Cybersecurity Operations

To understand Ether, consider the role of a traditional supervisory runtime: it schedules processes, manages memory bounds, abstracts tool interfaces via standardized drivers, enforces security boundaries, and provides predictable runtime guarantees.

**Ether applies this supervisory runtime model to cybersecurity tools and autonomous AI agents:**

| Supervisory Architecture Role | Ether Runtime Substrate |
| :--- | :--- |
| **Process Scheduler & Lifecycle** (`fork`/`exec`, cgroups) | **Async Process Supervisor**: Pure argument vectors (`create_subprocess_exec`), zero `shell=True`, 64KB log disk spooling (`LogSpooler`), and automatic `SIGTERM` $\to$ `SIGKILL` timeouts. |
| **Virtual Memory Management (VMM)** | **Bounded Memory Governor**: Strictly caps RAM consumption at **< 10MB** per active job using bounded ring buffers (`deque(maxlen=5000)`). |
| **Device Drivers** (`/dev/*` hardware modules) | **Pluggable Smart Adapters**: Decoupled drivers in `tools/<name>/` normalizing heterogenous CLI outputs into structured Pydantic finding schemas. |
| **Filesystem & Inodes** (ext4, deterministic paths) | **Deterministic GraphStore**: SQLite WAL engine indexing findings by deterministic SHA-256 **Primary Identity Keys (PIK)** ($H(\text{schema} + \text{sorted\_pik})$). |
| **Security Rings / Access Controls** | **Dual GatePolicy Seam**: Engine-level enforcement of `GatePolicy.SAFE` (SSRF/IMDS blocking, CIDR boundaries) vs `GatePolicy.UNRESTRICTED` (unconstrained execution for red-teams). |
| **Hardware State Invariance & Migration** | **Cryptographic Identity Anchoring & Temporal Decay**: Decouples volatile IPs via cryptographic fingerprints (`tls:`, `ssh:`, `favicon:`) and decays stale states (`confirmed` $\to$ `flapping` $\to$ `stale`). |
| **Embedded Hardware Acceleration** | **Zero-Egress Vector Memory (`sqlite-vec`)**: Embedded 384-dimensional unit vector engine for sub-millisecond semantic search without external model downloads or API egress. |
| **System Audit & Event Log** | **Forensic Event Log & Zero-Token Diffs**: Append-only event sourcing and set-theoretic graph deltas ($\Delta = S_{t+1} \setminus S_t$) cutting agent token usage by 98%. |
| **Userland Syscalls & IPC** (`read`, `write`, `ioctl`) | **Native Model Context Protocol (MCP)**, **Headless CLI**, and **Async Python SDK**. |

```
┌────────────────────────────────────────────────────────────────────────┐
│                   APPLICATIONS & AGENTS (Userland)                     │
│                                                                        │
│  [Autonomous AI Agents]        [CLI Operators]          [Custom SDK]   │
│  (Claude, Cursor, Swarms)    (Red-Teams / Scripts)    (Security Apps)  │
└────────────┬────────────────────────────┬───────────────────────┬──────┘
             │ (Model Context Protocol)   │ (Terminal CLI)        │ (Python)
             ▼                            ▼                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    ETHER UNIFIED SYSTEM CALL RUNTIME                   │
├────────────────────────────────────────────────────────────────────────┤
│                           ETHER RUNTIME CORE                           │
│                                                                        │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────┐  │
│  │ Process & Ring Governor │  │ Deterministic Reactive GraphStore   │  │
│  │ - Pure Argument Vectors │  │ - SHA-256 Primary Identity Keys     │  │
│  │ - 64KB Disk Spooler     │  │ - Idempotent Non-Destructive Upsert │  │
│  │ - <10MB RAM Ring Buffer │  │ - Temporal Decay & Identity Anchors │  │
│  │ - Secret Scrubbing      │  │ - Embedded Vector Memory (sqlite-vec)│ │
│  └─────────────────────────┘  └─────────────────────────────────────┘  │
│  ┌─────────────────────────┐  ┌─────────────────────────────────────┐  │
│  │ GatePolicy Enforcement  │  │ AI Telemetry & Injection Sandbox    │  │
│  │ - SAFE (SSRF/IMDS Def)  │  │ - Zero-Token Graph Diffs (98% cut)  │  │
│  │ - UNRESTRICTED Policy   │  │ - Neutralized Prompt Injection Bounds│ │
│  └─────────────────────────┘  └─────────────────────────────────────┘  │
│                                │                                       │
│                                ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Universal Device Driver Layer (Smart Adapters: tools/*)          │  │
│  │ - Tier A: In-Process Coroutines (http_probe, dnspython)          │  │
│  │ - Tier B: Binary Subprocesses (nmap, nuclei, ffuf, subfinder...) │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### The 6 Core Engine Subsystems

1. **Async Process Supervisor & Memory Governor**
   Spawns binaries strictly via pure argument vectors (`asyncio.create_subprocess_exec`) without shell interpolation (`shell=True`). Strips all host API keys and operator secrets (`OPENAI_*`, `AWS_*`, `SSH_*`) via `sanitize_subprocess_env`. Spools gigabytes of raw console output directly to disk with 64KB buffering while strictly capping in-memory ring buffers (`maxlen=5000`) below **10MB RAM**.

2. **Deterministic Entity State Machine**
   Entities (Hosts, Services, Vulnerabilities, Endpoints) are indexed by mathematical **Primary Identity Keys (PIKs)**. Node IDs are deterministic SHA-256 hashes of `(schema_type + sorted_pik)`. Ingesting the same finding across multiple tools non-destructively merges attributes into a single node rather than creating duplicate graph clutter.

3. **Cryptographic Identity Anchoring & Temporal State Decay**
   Decouples volatile IP addresses from logical service identities using invariant cryptographic fingerprints (`tls:<sha256>`, `ssh:<fingerprint>`, `favicon:<hash>`). When a service migrates across cloud IPs, Ether automatically links cross-IP identity migration edges (`anchored_identity`). Unseen nodes undergo automatic confidence state decay (`confirmed` $\to$ `flapping` $\to$ `stale`).

4. **Zero-Egress Embedded Vector Memory (`sqlite-vec`)**
   Discovered findings are automatically converted into 384-dimensional unit vectors stored inside SQLite via `sqlite-vec`'s `vec0` virtual table. Enables sub-millisecond k-NN semantic search and task-directed context retrieval for AI agents with **zero model downloads, zero external API keys, and zero network egress**.

5. **Dual-Mode Security Policy Seam (`GatePolicy`)**
   Provides first-class runtime policy enforcement:
   * `GatePolicy.SAFE`: Strictly blocks cloud metadata endpoints (AWS IMDSv2 `169.254.169.254`, GCP, Azure), enforces authorized CIDR scope guardrails, and strips credentials.
   * `GatePolicy.UNRESTRICTED`: Unlocks raw, unconstrained execution for authorized red-team engagements and advanced penetration testing operations.

6. **AI Prompt Injection Boundary Sandbox**
   Protects AI reasoning loops from malicious target payloads (e.g. prompt injection embedded in target HTTP headers, TLS certs, or HTML comments). Wraps untrusted target stdout inside structural `<untrusted_scan_output>` boundary tags, neutralizing breakout sequences (`</untrusted_scan_output>` escaped to `<\/untrusted_scan_output>`) and redacting private keys and bearer tokens.

---

## What Goals Can You Achieve with Ether?

### 1. Autonomous AI Agent Pentesting (Cursor / Claude Desktop / Swarms)
Connect LLM agents directly to Ether via the native **Model Context Protocol (MCP)**. Instead of flooding an LLM with 50,000 tokens of raw console logs, Ether returns **Zero-Token Diffs** ($\Delta = S_{t+1} \setminus S_t$) containing only newly discovered or mutated findings, cutting context consumption by **98%** while preventing prompt injection via structural `<untrusted_scan_output>` sandboxing.

### 2. Unified Attack Surface Mapping & Asset Discovery
Run multi-stage reconnaissance loops chaining passive DNS (`whois`, `dnspython`, `subfinder`), port scanning (`nmap`), and web probing (`http_probe`, `ffuf`). Ether automatically correlates all findings into a deterministic SQLite WAL graph using SHA-256 Primary Identity Keys (PIK), resolving cross-IP migrations and cryptographic service anchors.

### 3. Continuous CI/CD Security Regression Gates
Incorporate automated security validation into GitHub Actions or GitLab CI. Use `ether run` in CI pipelines to probe staging targets, assert zero high/critical vulnerabilities, and export cryptographically verifiable forensic logs with zero UI overhead.

### 4. Forensic Session Replay & Cryptographically Verified Audits
Every executed command and parsed finding is logged into an append-only event source. Export complete engagement sessions into password-protected, encrypted archives (AES-256-GCM + Argon2id) for compliance audits, client delivery, or post-incident review.

---

## Installation

### Prerequisites
- Python $\ge 3.11$
- Linux or macOS

```bash
# Option A: Install directly from PyPI
pip install ether-core
# (or with pipx for isolated global CLI access)
pipx install ether-core

# Option B: Clone for local development
git clone https://github.com/h45sh/ether.git
cd ether
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Install supervised external security tools (nmap, nuclei, ffuf, etc.)
./scripts/install_deps.sh
```

---

## How to Use Ether: 4 Core Methods

Ether is multi-modal by design. You can drive the engine through any of the following four interfaces:

### Method 1: The Headless CLI (For Operators & Shell Automation)

The `ether` CLI provides 10 high-leverage subcommands to manage workspaces, supervise scans, query the graph, search findings, and audit architectural drift:

```bash
# 1. Verify environment health and discovered security tools
ether doctor

# 2. Inspect available tool adapters (nmap, nuclei, ffuf, subfinder, etc.)
ether tool list

# 3. Create a dedicated investigation session
SESSION_ID=$(ether session create "Target Perimeter Recon" --json | jq -r '.session_id')

# 4. Supervise a tool scan (stdout is normalized streamingly into the graph)
ether run nmap 192.168.1.50 --session-id "$SESSION_ID" --params '{"raw_flags": "-sV -p 80,443,8080"}'

# 5. List discovered finding nodes in the session graph
ether graph list-nodes "$SESSION_ID"

# 6. Perform offline semantic vector search over findings (k-NN cosine distance)
ether graph search "$SESSION_ID" "Log4j RCE vulnerabilities or exposed web panels"

# 7. Extract token-budgeted AI telemetry snapshot
ether telemetry snapshot "$SESSION_ID" --budget 2000

# 8. Export forensic audit archive (encrypted with AES-256-GCM)
ether graph export "$SESSION_ID" -o engagement_backup.enc --encrypt --passphrase "StrongPassword123"

# 9. Audit architectural drift against an expected baseline
ether drift audit "$SESSION_ID" --baseline baseline.json --record
```

*For complete CLI reference and all flags, see the [Headless CLI Operations Guide](https://github.com/h45sh/ether/blob/main/docs/how-to/cli-usage.md).*

---

### Method 2: Native AI Agent MCP Server (For Claude Desktop, Cursor, & Swarms)

Ether provides a built-in **Model Context Protocol (MCP)** server over standard I/O (`stdio`) or Server-Sent Events (`sse`), exposing 15 tools: `execute_tool`, `query_graph`, `inspect_entity`, `get_diff`, `search_findings_semantic`, `abort_action`, `get_attack_path`, `get_blast_radius`, `get_crown_jewels`, `list_tools`, `get_tool_info`, `manage_session`, `read_action_log`, `get_deception_report`, and `audit_drift`.

#### Configure Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "ether": {
      "command": "/path/to/ether/.venv/bin/ether",
      "args": ["mcp"],
      "env": {
        "ETHER_DATA_DIR": "/home/user/.ether"
      }
    }
  }
}
```

#### Configure Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "ether": {
      "command": "/path/to/ether/.venv/bin/ether",
      "args": ["mcp"]
    }
  }
}
```

#### Prompting Your AI Agent
Once connected, give your agent natural language cybersecurity tasks:
> *"Perform an initial recon of 10.10.10.25. Run nmap to discover web services, inspect the graph for findings, and search for potential remote code execution vectors."*

The agent will autonomously invoke `execute_tool`, retrieve zero-token graph deltas via `get_diff`, and query vector memory via `search_findings_semantic` without flooding its context window.

*For complete MCP instructions, see the [Agent Telemetry & MCP Guide](https://github.com/h45sh/ether/blob/main/docs/how-to/agent-telemetry-mcp.md).*

---

### Method 3: Python Async SDK (For Custom Applications & Pipelines)

Embed Ether directly into your Python scripts or custom security platforms:

```python
import asyncio
from ether import ActionGateway, GatePolicy, GraphStore, ToolRegistry
from ether.schemas.network import NetworkHost, NetworkService


async def main():
    # 1. Initialize SQLite WAL Storage (in-memory or persistent disk path)
    store = GraphStore(":memory:")
    await store.initialize()

    # 2. Create Workspace and Session
    ws_id = await store.create_workspace("Engagement Alpha")
    sess_id = await store.create_session(ws_id, "External Surface Recon")

    # 3. Discover Pluggable Tool Adapters
    registry = ToolRegistry()
    registry.load_tools()

    # 4. Enforce Security Gate Policy (SAFE for defensive scopes, UNRESTRICTED for red-teams)
    gateway = ActionGateway(registry, store, policy=GatePolicy.SAFE)

    # 5. Insert Discovered Entity Findings
    host = NetworkHost.create(ip="10.10.10.5", hostname="target.internal")
    await store.upsert_finding(sess_id, host)

    service = NetworkService.create(
        host_ip="10.10.10.5",
        port=80,
        protocol="tcp",
        service_name="http",
        banner="nginx/1.18.0",
    )
    node_id = await store.upsert_finding(sess_id, service)

    # 6. Query Graph Nodes
    nodes = await store.get_all_nodes(sess_id)
    print(f"Discovered {len(nodes)} entities in session graph.")

    # 7. Semantic k-NN Search over findings via sqlite-vec
    results = await store.semantic_search(sess_id, "HTTP web server", limit=5)
    for r in results:
        print(f"Matched Node [{r['node_id']}]: Distance {r['distance']:.4f}")

    await store.close()


if __name__ == "__main__":
    asyncio.run(main())
```

---

### Method 4: Docker Container (For Containerized & Cloud Workflows)

Run Ether as a multi-arch OCI container image pre-loaded with all security binaries (`nmap`, `nuclei`, `subfinder`, `ffuf`, `nikto`, `sqlmap`, `searchsploit`):

```bash
# Build the Docker image locally
docker build -t ether:latest .

# Run CLI diagnostic check inside container
docker run --rm -v ~/.ether:/root/.ether ether:latest doctor

# Run an external scan and persist the graph state to host volume
docker run --rm -v ~/.ether:/root/.ether ether:latest run nmap 192.168.1.50

# Run MCP server over stdio for containerized agents
docker run -i --rm -v ~/.ether:/root/.ether ether:latest mcp
```

---

## Architectural Guarantees & Invariants

Ether strictly adheres to the following mechanical engineering contracts:

| Invariant | Technical Implementation | Guarantee |
| :--- | :--- | :--- |
| **Strict Headless Core** | Zero Textual, curses, or UI imports | Verified via AST linting (`pytest -m tier0`). Pure headless engine. |
| **Process Isolation** | Pure argument vectors (`asyncio.create_subprocess_exec`) | Zero `shell=True`. 100% immune to shell injection. |
| **Bounded Memory Ceiling** | Bounded ring buffers (`maxlen=5000`) & 64KB disk spooling | Memory usage strictly capped at **<10MB** per active job. |
| **Secret Scrubbing** | Child environment scrubbing (`sanitize_subprocess_env`) | Host API keys (`OPENAI_*`, `AWS_*`, `SSH_*`) never leak to child tools. |
| **Deterministic State** | Primary Identity Key (PIK) hashing via SHA-256 | Non-destructive idempotent entity merging in SQLite WAL. |
| **Zero-Token Diffs** | Set-theoretic delta calculation ($\Delta = S_{t+1} \setminus S_t$) | Cuts LLM agent context window consumption by **98%**. |
| **Dual Policy Seam** | `GatePolicy.SAFE` vs `GatePolicy.UNRESTRICTED` | Defends against SSRF & cloud metadata theft; unlocks unconstrained execution for red-teams. |
| **Offline Vector RAG** | Native `sqlite-vec` k-NN search (384-dimensional) | High-speed semantic search with zero network egress or external API calls. |

---

## Universal Smart Adapter Ecosystem

Ether decouples command building and parsing into pluggable tool adapters located in `tools/<name>/`:

| Tool | Category | Execution Tier | Normalized Schemas Produced |
| :--- | :--- | :--- | :--- |
| **`nmap`** | Port & Service Scanning | Subprocess (Tier B) | `network.host`, `network.service` |
| **`nuclei`** | Vulnerability Scanning | Subprocess (Tier B) | `vulnerability.found` |
| **`ffuf`** | Web Fuzzing & Directory Discovery | Subprocess (Tier B) | `web.endpoint` |
| **`gobuster`** | URI & DNS Enumeration | Subprocess (Tier B) | `web.endpoint`, `dns.record` |
| **`subfinder`** | Passive Subdomain Discovery | Subprocess (Tier B) | `dns.record`, `domain.info` |
| **`nikto`** | Web Server Vulnerability Scanner | Subprocess (Tier B) | `vulnerability.found`, `audit.misconfig` |
| **`sqlmap`** | Database Vulnerability Scanner | Subprocess (Tier B) | `vulnerability.found` |
| **`searchsploit`** | Exploit-DB Offline Search | Subprocess (Tier B) | `exploit.reference` |
| **`whois`** | Network Range & ASN Lookup | Subprocess (Tier B) | `network.netblock`, `domain.info` |
| **`netexec`** | Active Directory & Network Auditing | Subprocess (Tier B) | `network.host`, `credential.found` |
| **`dnspython`** | DNS Records & Zone Transfers | Native Coroutine (Tier A) | `dns.record`, `domain.info` |
| **`http_probe`** | HTTP Surface & Favicon Probing | Native Coroutine (Tier A) | `web.endpoint`, `web.technology` |

*To build or scaffold your own tool adapter, consult the [Adapter Authoring Guide](https://github.com/h45sh/ether/blob/main/docs/how-to/author-adapters.md) and use the official [Ether DevKit (`ether-devkit`)](https://github.com/h45sh/ether-devkit) developer CLI & agent skill (`pipx install git+https://github.com/h45sh/ether-devkit.git` or `npx skills add h45sh/ether-devkit`).*

---

## Testing & Verification

Ether operates on the **"Review Proof, Not Code"** engineering model. Every release must pass 100% of mechanical verification gates:

```bash
# Execute the comprehensive 6-stage release preflight check
./scripts/release-check.sh

# Run Tier 0 AST Invariants & Property-Based Tests (<2s)
pytest -m tier0

# Run Universal Adapter Fuzzing Suite across all tool adapters
pytest -m fuzz

# Run Full Regression Suite (284 tests)
pytest tests/

# Evaluate Performance Limits & Benchmark Invariants
python3 tests/benchmarks/runner.py --check

# Run In-Tree AST Mutation Testing
python3 tests/mutation/run_mutation_tests.py --target=canonicalize
```

---

## Documentation Hub (Diátaxis Framework)

Ether’s documentation is structured according to the **[Diátaxis Framework](https://diataxis.fr/)**:

```text
                                  PRACTICAL (Doing)
                                         ▲
                                         │
               Tutorials                 │             How-To Guides
          (Learning-Oriented)            │          (Problem-Oriented)
       "Show me how to get started"      │      "Show me how to solve a task"
       - [Quickstart Tutorial]           │      - [Headless CLI Operations]
         (docs/tutorials/quickstart.md)  │        (docs/how-to/cli-usage.md)
                                         │      - [Agent Telemetry & MCP]
                                         │        (docs/how-to/agent-telemetry-mcp.md)
                                         │      - [Authoring Tool Adapters]
                                         │        (docs/how-to/author-adapters.md)
                                         │      - [Contributing Guidelines]
                                         │        (docs/CONTRIBUTING.md)
     ────────────────────────────────────┼────────────────────────────────────
                                         │
                 Explanation             │               Reference
          (Understanding-Oriented)       │         (Information-Oriented)
        "Help me understand the why"     │     "Give me the technical specs"
        - [Architecture Deep Dive]       │     - [Schema Registry (18 Models)]
          (docs/explanation/architecture.md)      (docs/reference/schema-registry.md)
        - [Database & Graph State]       │     - [Engineering Standards]
          (docs/explanation/database.md) │        (docs/reference/engineering-standards.md)
        - [Performance Benchmarks]       │     - [Domain Glossary]
          (docs/benchmarks/README.md)    │        (docs/reference/glossary.md)
                                         │     - [Master Roadmap (5 Epochs)]
                                         │        (ROADMAP.md)
                                         ▼
                                 THEORETICAL (Knowing)
```

---

## License

Ether is released under the **MIT License**. See [LICENSE](https://github.com/h45sh/ether/blob/main/LICENSE) for details.
