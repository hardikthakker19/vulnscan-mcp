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
- 🚀 **Triple Transport** — `stdio` for local IDE agents, `sse` + `streamable-http` on port 8001 for network agents
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

# Network mode on port 8001 — serves both SSE and Streamable HTTP simultaneously
uv run vulnscan-mcp --transport sse --port 8001
```

When running in network mode, the server exposes:
- **SSE** at `/sse` (+ `/messages` for POST)
- **Streamable HTTP** at `/mcp`
- **Health check** at `/`

### Docker

```bash
docker compose up -d
# SSE endpoint:              http://localhost:8001/sse
# Streamable HTTP endpoint:  http://localhost:8001/mcp
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

### Cursor / Remote Agents (SSE)

```bash
docker run -d -p 8001:8001 -v $(pwd)/data:/app/data --env-file .env vulnscan-mcp:latest
```

Connect to: `http://localhost:8001/sse`

### ChatGPT / OpenAI (Streamable HTTP)

The server supports [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http) transport at the `/mcp` endpoint, which is the protocol used by ChatGPT and the OpenAI Responses API.

**ChatGPT Plugin:**

Add as a remote MCP server in ChatGPT settings using the URL:

```
https://your-domain.com/mcp
```

**OpenAI Responses API:**

```python
from openai import OpenAI

client = OpenAI()

resp = client.responses.create(
    model="gpt-4o",
    tools=[
        {
            "type": "mcp",
            "server_label": "vulnscan",
            "server_description": "Vulnerability Intelligence MCP Server",
            "server_url": "https://your-domain.com/mcp",
            "require_approval": "never",
        },
    ],
    input="What are the latest critical CVEs from the past 7 days?",
)

print(resp.output_text)
```

> **Note:** ChatGPT requires your server to be reachable over HTTPS. For local/private servers, use [OpenAI's Secure MCP Tunnel](https://platform.openai.com/api/docs/guides/secure-mcp-tunnels) to expose your server without making it publicly accessible.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | — | NVD API key for higher rate limits |
| `MCP_TRANSPORT` | `sse` | Transport: `stdio`, `sse`, `http`, or `streamable-http` |
| `MCP_PORT` | `8001` | Network server port (serves both SSE and Streamable HTTP) |
| `NVD_SYNC_INTERVAL_HOURS` | `2` | NVD delta sync interval |
| `KEV_SYNC_INTERVAL_HOURS` | `12` | CISA KEV sync interval |
| `EPSS_SYNC_INTERVAL_HOURS` | `24` | EPSS batch enrichment interval |

## License

MIT
