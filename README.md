# vulnscan-mcp

**Vulnerability Intelligence MCP Server** — an enterprise-grade Model Context Protocol server providing AI agents with real-time, correlated vulnerability intelligence.

## Overview

`vulnscan-mcp` unifies data from four intelligence sources into a single normalized data fabric:

- **NIST NVD 2.0** — CVE details, CVSS scores, CWE classifications, CPE patterns
- **CISA KEV** — Known Exploited Vulnerabilities catalog with active exploitation status
- **FIRST.org EPSS** — Exploit Prediction Scoring System probability scores
- **MITRE ATT&CK** — Adversary tactic and technique mappings

## Features

- 🔍 **5 MCP Tools** for vulnerability search, CVE details, critical CVE tracking, KEV monitoring, and EPSS scoring
- 🔄 **Automated Background Sync** — NVD delta (2h), CISA KEV (12h), EPSS batch (24h) via APScheduler
- 💾 **SQLite + FTS5** — Full-text search with 67K+ pre-loaded CVE records
- 🚀 **Dual Transport** — `stdio` for local IDE agents, `sse` on port 8001 for network agents
- 🐳 **Docker Ready** — Multi-stage build with non-root user

## Quick Start

### Prerequisites
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) package manager

### Installation

```bash
# Clone and install
git clone <repo-url> vulnscan-mcp
cd vulnscan-mcp
cp .env.example .env
# Edit .env with your NVD API key
uv sync
```

### Running

```bash
# stdio mode (for Claude Desktop, Claude Code)
uv run vulnscan-mcp --transport stdio

# SSE mode on port 8001 (for Cursor, remote agents)
uv run vulnscan-mcp --transport sse --port 8001
```

### Docker

```bash
docker compose up -d
# Server available at http://localhost:8001/sse
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `search_vulnerabilities` | Search CVEs by keyword, severity, date range, KEV status |
| `get_cve_details` | Deep 360° enriched profile for a specific CVE |
| `get_latest_critical_cves` | Recently published critical vulnerabilities |
| `get_top_kevs` | Top actively exploited vulnerabilities from CISA KEV |
| `get_epss_score` | EPSS exploitation probability for one or more CVEs |

## AI Client Integration

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "uv",
      "args": [
        "--directory", "/path/to/vulnscan-mcp",
        "run", "vulnscan-mcp",
        "--transport", "stdio"
      ],
      "env": {
        "NVD_API_KEY": "your_key_here"
      }
    }
  }
}
```

### Cursor / Remote Agents (SSE on Port 8001)

```bash
docker run -d -p 8001:8001 -v $(pwd)/data:/app/data --env-file .env vulnscan-mcp:latest
```

Connect to: `http://localhost:8001/sse`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | — | NVD API key for higher rate limits |
| `MCP_TRANSPORT` | `sse` | Transport: `stdio` or `sse` |
| `MCP_PORT` | `8001` | SSE server port |
| `NVD_SYNC_INTERVAL_HOURS` | `2` | NVD delta sync interval |
| `KEV_SYNC_INTERVAL_HOURS` | `12` | CISA KEV sync interval |
| `EPSS_SYNC_INTERVAL_HOURS` | `24` | EPSS batch enrichment interval |

## License

MIT
