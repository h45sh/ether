import asyncio
import json
import sys
from pathlib import Path

import pytest
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent.parent
ETHER_CLI_BIN = Path(sys.executable).parent / "ether"


async def main():
    if ETHER_CLI_BIN.exists():
        server_cmd = str(ETHER_CLI_BIN)
        server_args = ["mcp"]
    else:
        server_cmd = sys.executable
        server_args = ["-m", "ether.cli.router", "mcp"]

    server_params = StdioServerParameters(
        command=server_cmd,
        args=server_args,
        env=None,
    )

    print("Connecting to Ether MCP Server over stdio...")
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            print("[+] Successfully initialized MCP Session with Ether!")

            # 1. List MCP Tools
            tools_response = await session.list_tools()
            print(f"[+] Discovered {len(tools_response.tools)} MCP Tools:")
            for tool in sorted(tools_response.tools, key=lambda t: t.name):
                summary = tool.description.splitlines()[0] if tool.description else ""
                print(f"    - {tool.name}: {summary}")

            # 2. Manage Session (Create investigation session)
            print("\n[*] Creating dedicated investigation session via MCP...")
            sess_res = await session.call_tool(
                "manage_session",
                arguments={"action": "create", "name": "MCP Automated Security Assessment"},
            )
            sess_data = json.loads(sess_res.content[0].text)
            session_id = sess_data["session_id"]
            print(f"[+] Created Session ID: {session_id}")

            # 3. Execute Tool via MCP (Run nmap security task on localhost)
            print("\n[*] Executing security task: nmap against 127.0.0.1...")
            exec_res = await session.call_tool(
                "execute_tool",
                arguments={
                    "tool_name": "nmap",
                    "target": "127.0.0.1",
                    "session_id": session_id,
                    "raw_flags": "-p 631,3306",
                },
            )
            exec_data = json.loads(exec_res.content[0].text)
            print(f"[+] Execution Status: {exec_data.get('status')}")
            print(f"    Action ID: {exec_data.get('action_id')}")
            print(f"    Duration: {exec_data.get('duration_ms')}ms")
            print(f"    Findings Count: {exec_data.get('findings_count')}")

            action_id = exec_data.get("action_id")

            # 4. Zero-Token Telemetry Diff
            print("\n[*] Fetching Zero-Token Graph Diff (Delta = S_{t+1} \\ S_t)...")
            diff_res = await session.call_tool(
                "get_diff", arguments={"action_id": action_id, "session_id": session_id}
            )
            diff_data = json.loads(diff_res.content[0].text)
            added_nodes = diff_data.get("added_nodes", [])
            print(f"[+] Added Nodes in Delta: {len(added_nodes)}")
            for node in added_nodes:
                print(
                    f"    - [{node.get('schema_type')}] Node ID: {node.get('id')} | PIK: {node.get('pik')}"
                )

            # 5. Query Graph
            print("\n[*] Querying Graph Entities...")
            query_res = await session.call_tool(
                "query_graph", arguments={"session_id": session_id, "limit": 10}
            )
            query_data = json.loads(query_res.content[0].text)
            print(f"[+] Total Nodes in Graph: {query_data.get('total')}")
            for node in query_data.get("nodes", []):
                print(
                    f"    - {node['schema_type']}: {node.get('pik')} (Status: {node.get('status')})"
                )

            # 6. Semantic Vector Search
            print("\n[*] Performing Zero-Egress Semantic Vector Search ('database services')...")
            search_res = await session.call_tool(
                "search_findings_semantic",
                arguments={
                    "query": "database services or MySQL listening port",
                    "session_id": session_id,
                    "limit": 3,
                },
            )
            search_data = json.loads(search_res.content[0].text)
            matched = search_data.get("findings", [])
            print(f"[+] Semantic Search Results (Found {len(matched)} matches):")
            for r in matched:
                print(
                    f"    - Similarity: {r.get('similarity'):.4f} | Type: {r.get('schema_type')} | ID: {r.get('id')} | PIK: {r.get('pik')}"
                )

            # 7. Crown Jewels & Attack Path Analytics
            print("\n[*] Running Graph Analytics: Crown Jewels...")
            cj_res = await session.call_tool(
                "get_crown_jewels", arguments={"session_id": session_id}
            )
            cj_data = json.loads(cj_res.content[0].text)
            print(
                f"[+] Crown Jewels Analysis complete. Crown Jewels found: {len(cj_data.get('crown_jewels', []))}"
            )

            print("\n[✓] All MCP & Security Tasks Completed Successfully!")


@pytest.mark.asyncio
async def test_mcp_client_stdio():
    """Verify live stdio MCP client interaction end-to-end."""
    await main()


if __name__ == "__main__":
    asyncio.run(main())
