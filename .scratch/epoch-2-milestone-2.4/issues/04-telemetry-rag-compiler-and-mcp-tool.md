# 04: Agent Telemetry RAG Integration & MCP Semantic Search Tool

**What to build:**
1. In `src/ether/graph/telemetry.py`:
   - Update `compile_telemetry_snapshot(self, ..., objective: Optional[str] = None)`:
   - When an `objective` (or task intent) is provided, query `store.semantic_search(self.session_id, objective, limit=5)` and inject top matching findings into `rag_findings` in the snapshot dictionary.
2. In `src/ether/mcp/server.py`:
   - Register native MCP tool:
     ```python
     @server.tool()
     async def search_findings_semantic(
         query: str,
         session_id: Optional[str] = None,
         limit: int = 10,
         schema_type: Optional[str] = None,
         min_score: float = 0.0,
     ) -> str:
     ```
   - Returns structured JSON with matched findings, PIK attributes, and similarity scores.
3. Write unit tests in `tests/unit/test_vector_rag.py`.

**Blocked by:** 03: `GraphStore` Vector Indexing & Semantic Search Engine

**Status:** completed

- [x] Add `objective` parameter and RAG finding injection to `compile_telemetry_snapshot()`
- [x] Add `search_findings_semantic` tool to MCP server in `src/ether/mcp/server.py`
- [x] Write unit tests in `tests/unit/test_vector_rag.py` verifying RAG snapshotting and MCP tool execution
