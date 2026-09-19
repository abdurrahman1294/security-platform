# V5.2.0 — Capability Depth

## Added (all at once)
1. **Registered adapter pack** — nmap, naabu, httpx, nuclei, katana, subfinder via `tools.run` only
2. **Expanded findings parsers** — nikto, sqlmap, gobuster, masscan (+ prior nmap/nuclei/httpx)
3. **Governed local MCP** — JSON-RPC tools/list + tools/call; no shell; loopback-oriented
4. **LLM supervisor** — propose-only (heuristic; BYO keys annotated, no auto-exec)
5. **Retest / regression** — SQLite snapshots + diff
6. **Report pack** — executive Markdown + HTML
7. **Lab benchmark harness** — self-check of the above without external network

## Governance
Authorization, scope, registered adapters only. Supervisor never executes tools.
