# 05: CLI `ether graph search` Subcommand & Complete Verification Matrix

**What to build:**
1. In `src/ether/cli/router.py`:
   - Add `search` subcommand under `ether graph`:
     `ether graph search <session_id> "<query>" [--limit 10] [--min-score 0.0] [--type <schema_type>]`
2. In `src/ether/cli/commands/graph.py`:
   - Implement `handle_graph_search(args, context)` displaying a formatted table or JSON of semantic search results (similarity score, node ID, schema type, target/PIK, summary).
3. Run the complete mechanical verification suite:
   - `pytest -m tier0`
   - `pytest -m fast`
   - `pytest -m fuzz`
   - Full `pytest tests/`
   - `ruff check .`
4. Update `ROADMAP.md` marking Milestone 2.4 complete and prepare merge into `main`.

**Blocked by:** 04: Agent Telemetry RAG Integration & MCP Semantic Search Tool

**Status:** ready-for-agent

- [ ] Add `search` parser to `src/ether/cli/router.py`
- [ ] Implement `handle_graph_search` in `src/ether/cli/commands/graph.py`
- [ ] Add CLI tests in `tests/unit/test_cli.py` verifying `ether graph search`
- [ ] Pass all mechanical gates (`tier0`, `fast`, `fuzz`, full `pytest`, `ruff check .`)
- [ ] Update `ROADMAP.md`
