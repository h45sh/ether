import asyncio
import json
import sys
import tempfile
from pathlib import Path

import pytest
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent.parent
ETHER_CLI_BIN = Path(sys.executable).parent / "ether"


async def main():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = str(Path(tmp_dir) / "mcp_client_test.db")
        if ETHER_CLI_BIN.exists():
            server_cmd = str(ETHER_CLI_BIN)
            server_args = ["mcp", "--db", db_path, "--data-dir", tmp_dir]
        else:
            server_cmd = sys.executable
            server_args = ["-m", "ether.cli.router", "mcp", "--db", db_path, "--data-dir", tmp_dir]

        import os

        server_env = dict(os.environ)
        server_env.setdefault("ETHER_PLUGIN_TRUST_MODE", "dev")
        server_params = StdioServerParameters(
            command=server_cmd,
            args=server_args,
            env=server_env,
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # 1. List MCP Tools
                tools_response = await session.list_tools()
                tool_names = {t.name for t in tools_response.tools}
                assert "execute_tool" in tool_names
                assert "query_graph" in tool_names

                # 2. Manage Session (Create investigation session)
                sess_res = await session.call_tool(
                    "manage_session",
                    arguments={"action": "create", "name": "MCP Automated Security Assessment"},
                )
                assert not sess_res.is_error
                sess_data = json.loads(sess_res.content[0].text)
                session_id = sess_data["session_id"]
                assert session_id

                # 3. Execute Tool via MCP using valid arguments={"flags": ...}
                exec_res = await session.call_tool(
                    "execute_tool",
                    arguments={
                        "tool_name": "nmap",
                        "target": "127.0.0.1",
                        "session_id": session_id,
                        "arguments": {"flags": ["-p", "631,3306"]},
                    },
                )
                assert not exec_res.is_error
                exec_data = json.loads(exec_res.content[0].text)
                assert "status" in exec_data or "is_error" in exec_data

                action_id = exec_data.get("action_id")
                if action_id:
                    # 4. Zero-Token Telemetry Diff
                    diff_res = await session.call_tool(
                        "get_diff", arguments={"action_id": action_id, "session_id": session_id}
                    )
                    assert not diff_res.is_error
                    diff_data = json.loads(diff_res.content[0].text)
                    assert "added_nodes" in diff_data

                # 5. Query Graph
                query_res = await session.call_tool(
                    "query_graph", arguments={"session_id": session_id, "limit": 10}
                )
                assert not query_res.is_error
                query_data = json.loads(query_res.content[0].text)
                assert "total" in query_data
                assert "nodes" in query_data

                # 6. Semantic Vector Search
                search_res = await session.call_tool(
                    "search_findings_semantic",
                    arguments={
                        "query": "database services or MySQL listening port",
                        "session_id": session_id,
                        "limit": 3,
                    },
                )
                assert not search_res.is_error
                search_data = json.loads(search_res.content[0].text)
                assert "findings" in search_data

                # 7. Crown Jewels & Attack Path Analytics
                cj_res = await session.call_tool(
                    "get_crown_jewels", arguments={"session_id": session_id}
                )
                assert not cj_res.is_error
                cj_data = json.loads(cj_res.content[0].text)
                assert "crown_jewels" in cj_data


@pytest.mark.asyncio
async def test_mcp_client_stdio():
    """Verify live stdio MCP client interaction end-to-end."""
    await main()


if __name__ == "__main__":
    asyncio.run(main())
