# Vulnerability Intelligence MCP Server (vulnscan-mcp)
## Strategic Architecture & Implementation Specification for Antigravity IDE

---

## 1. Executive Summary & Objectives

The **Vulnerability Intelligence MCP Server (`vulnscan-mcp`)** is an enterprise-grade Model Context Protocol (MCP) server engineered to provide AI agents (Claude Code, Cursor, OpenAI ChatGPT, custom agentic workflows) with real-time, correlated vulnerability intelligence. 

By unifying National Vulnerability Database (NVD) entries, CISA Known Exploited Vulnerabilities (KEV), FIRST.org Exploit Prediction Scoring System (EPSS), and MITRE ATT&CK adversary technique mappings into a single normalized data fabric, `vulnscan-mcp` empowers AI assistants to perform deep security triage, prioritize zero-days, evaluate exposure, and recommend actionable remediation paths.

### Primary Objectives
- **Multi-Source Correlation:** Stitch CVE details (NVD 2.0) with real-world active exploitation status (CISA KEV), exploitation probability (FIRST EPSS), and adversary tradecraft (MITRE ATT&CK).
- **Automated Periodic Ingestion & Synchronization:** Run background scheduled jobs (via `APScheduler`) that continuously ingest and sync CVEs from NVD (delta fetch), CISA KEV, and EPSS into the local SQLite database without blocking client requests.
- **Hybrid Storage & Fast Retrieval:** Leverage existing historical data in `.data/vulnscan.db` (SQLite) enhanced with FTS5 (Full-Text Search) and delta state tracking.
- **Standards-Compliant MCP Interface:** Expose structured, low-latency MCP tools over both `stdio` (local IDE agents like Claude Code) and Server-Sent Events / HTTP (`sse` / `streamable` on **Port 8001**).
- **Modern Packaging & Deterministic Builds:** Standardize on Astral's `uv` for blazing-fast dependency resolution and virtual environment management.
- **Production Containerization:** Provide a minimal, secure, non-root Docker deployment configured on port **8001** with persistent volume mounts and dynamic `.env` configuration.

---

## 2. Source Data Fabric & Integration Matrix

| Data Source | Ingestion Mechanism | Periodic Schedule | Primary Attributes Provided | Fallback & Rate-Limit Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **NIST NVD 2.0** | REST API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) + SQLite Local DB | Delta sync every **2 hours** (configurable) | CVE ID, CVSS v3.1/v4.0 metrics, severity, descriptions, CWE classifications, vendor CPEs, reference advisories. | Local `.data/vulnscan.db` cache first. API key in `.env` (`NVD_API_KEY`) unlocks 50 requests/30s window (vs 5 req/30s unauthenticated). Exponential backoff on 403/429. |
| **CISA KEV** | HTTP JSON Stream (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) | Ingestion every **12 hours** | Known exploited status, vendor/product, date added to KEV, mandatory remediation due dates, required action, ransomware flag. | In-memory set / SQLite index refreshed at startup and on schedule. Graceful offline fallback to last synced cache. |
| **FIRST.org EPSS** | REST API (`https://api.first.org/data/v1/epss?cve={cve_id}`) | Batch pre-fetch every **24 hours** + on-demand | EPSS probability score (0.0 to 1.0), percentile ranking. | Batch query support (`cve=CVE-1,CVE-2`) up to 100 CVEs per request. Local LRU/SQLite cache with 24-hour TTL. |
| **MITRE ATT&CK** | Curated JSON mapping via CAPEC-to-ATT&CK & direct CVE references | Startup validation & periodic weekly check | Tactics (e.g., Initial Access), Techniques/Sub-techniques (e.g., T1190, T1068), detection guidance. | Embedded static JSON mapping database updated via scheduled build script or local lookup table. |

---

## 3. High-Level System Architecture

```
                      +------------------------------------------+
                      |   AI Client / Agent (Claude Code,        |
                      |   Cursor, OpenAI ChatGPT, IDE)          |
                      +--------------------+---------------------+
                                           |
                              JSON-RPC 2.0 | (MCP Protocol)
                     [stdio / SSE:8001]    |
                                           v
+----------------------------------------------------------------------------------+
| vulnscan-mcp Container / Service (Port 8001)                                     |
|                                                                                  |
|  +----------------------------------------------------------------------------+  |
|  | FastMCP Server Engine (Async Python 3.12 + Pydantic v2)                    |  |
|  |  * Tool Router & Schema Validation                                         |  |
|  |  * Error Handling & Normalized Response Serializer                         |  |
|  +--------------------------------------+-------------------------------------+  |
|                                         |                                        |
|  +--------------------------------------v-------------------------------------+  |
|  | Orchestration & Data Fusion Layer                                          |  |
|  |  - Correlates NVD records + CISA KEV + EPSS score + ATT&CK techniques       |  |
|  |  - Applies search filters: keyword, severity, pubDate, hasKev, limit       |  |
|  +-------------------+--------------------------------------------------------+  |
|                      |                                                           |
|       [Instant Read] |                                                           |
|                      v                                                           |
|  +-----------------------------------+       +--------------------------------+  |
|  | Local SQLite Storage              |<======| Background Periodic Sync       |  |
|  | (.data/vulnscan.db)               | Ingest| Engine (Async APScheduler)     |  |
|  |  - cves (Core Historical + Delta) |       |  * NVD Delta (every 2h)        |  |
|  |  - cves_fts (FTS5 Index)          |       |  * CISA KEV Feed (every 12h)   |  |
|  |  - cisa_kev (Catalog)             |       |  * EPSS Score Batch (every 24h)|  |
|  |  - epss_cache (TTL 24h)           |       +---------------+----------------+  |
|  |  - sync_state (Tracking & Offsets)|                       |                   |
|  +-----------------------------------+                       | Periodic HTTPS    |
|                                                              v                   |
|                                      +----------------------------------------+  |
|                                      | Upstream Intelligence APIs (httpx)     |  |
|                                      |  - NVD REST API 2.0 (with API Key)     |  |
|                                      |  - CISA KEV Feed (JSON Engine)         |  |
|                                      |  - FIRST.org EPSS API (Batch / Single) |  |
|                                      |  - MITRE ATT&CK Cross-Reference Cache  |  |
|                                      +----------------------------------------+  |
+----------------------------------------------------------------------------------+
```

---

## 4. Periodic Synchronization Pipeline Architecture

To prevent API rate-limits and eliminate latency during agent interactions, `vulnscan-mcp` utilizes an **asynchronous background synchronization pipeline** managed by `APScheduler`.

### 4.1. Sync Engine Components
1. **Delta Tracker (`sync_state` Table):** Maintains high-water marks (timestamps) for each data source so sync jobs only download changes since the last run.
2. **NVD Incremental Poller:**
   - **Cadence:** Every 2 hours (configurable via `NVD_SYNC_INTERVAL_HOURS`).
   - **Method:** Fetches records modified between `last_sync_timestamp` and `datetime.utcnow()` via:
     ```
     https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={last_sync}&lastModEndDate={now}
     ```
   - **Pagination:** Handles `startIndex` and `resultsPerPage` up to 2,000 items per window.
   - **Storage:** Upserts new and modified CVEs into `cves`, which automatically triggers updates in `cves_fts`.
3. **CISA KEV Scheduled Ingest:**
   - **Cadence:** Every 12 hours (configurable via `KEV_SYNC_INTERVAL_HOURS`).
   - **Method:** Downloads full catalog, checks `catalogVersion` or ETag header, and executes batch upsert into `cisa_kev`.
4. **EPSS Background Enrichment:**
   - **Cadence:** Every 24 hours.
   - **Method:** Collects all CVEs from `cisa_kev` plus any critical CVEs added in the last 30 days, splits them into 50-item batches, calls `https://api.first.org/data/v1/epss?cve={batch}`, and updates `epss_cache`.

### 4.2. Database Sync State Schema
```sql
CREATE TABLE IF NOT EXISTS sync_state (
    source_name TEXT PRIMARY KEY, -- 'NVD', 'CISA_KEV', 'EPSS'
    last_sync_timestamp TEXT NOT NULL,
    records_synced INTEGER DEFAULT 0,
    sync_status TEXT DEFAULT 'SUCCESS', -- 'SUCCESS', 'RUNNING', 'FAILED'
    error_message TEXT
);
```

---

## 5. MCP Tools Specification

The server exposes 5 core tools for AI agents. All parameters are strongly typed and validated.

### 5.1. `search_vulnerabilities`
Search and filter vulnerabilities across local storage and synchronized feeds.

* **Tool Name:** `search_vulnerabilities`
* **Input Schema:**
  ```python
  class SearchVulnerabilitiesInput(BaseModel):
      keyword: Optional[str] = Field(
          None,
          description="Search term matching CVE ID, vulnerable component, vendor, or description (e.g., 'apache log4j', 'buffer overflow', 'openssl')."
      )
      severity: Optional[Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]] = Field(
          None, 
          description="Filter by qualitative CVSS v3/v4 severity rating."
      )
      pubStartDate: Optional[str] = Field(
          None, 
          description="Start publication date in ISO-8601 format (e.g., '2024-01-01' or '2024-01-01T00:00:00Z')."
      )
      pubEndDate: Optional[str] = Field(
          None, 
          description="End publication date in ISO-8601 format (e.g., '2024-12-31' or '2024-12-31T23:59:59Z')."
      )
      hasKev: Optional[bool] = Field(
          False, 
          description="If True, filters strictly for CVEs confirmed present in the CISA Known Exploited Vulnerabilities catalog."
      )
      limit: int = Field(
          20, 
          ge=1, 
          le=50, 
          description="Maximum number of vulnerability records to return (1-50, default: 20)."
      )
  ```

### 5.2. `get_cve_details`
Retrieve a comprehensive, deeply enriched 360-degree security profile for an individual CVE.

* **Tool Name:** `get_cve_details`
* **Input Schema:**
  ```python
  class GetCveDetailsInput(BaseModel):
      cve_id: str = Field(
          ..., 
          regex=r"^CVE-\d{4}-\d{4,}$", 
          description="Standardized CVE identifier (e.g., 'CVE-2021-44228', 'CVE-2024-3094')."
      )
  ```
* **Enriched Output:** NVD CVSS scores + CISA KEV active exploitation flags + FIRST.org EPSS exploitation probability + MITRE ATT&CK tactics/techniques.

### 5.3. `get_latest_critical_cves`
Fetch newly published critical vulnerabilities from the synchronized database.

* **Tool Name:** `get_latest_critical_cves`
* **Input Schema:**
  ```python
  class GetLatestCriticalInput(BaseModel):
      days: int = Field(
          7, 
          ge=1, 
          le=90, 
          description="Past calendar days to search (default: 7)."
      )
      min_cvss: float = Field(
          9.0, 
          ge=7.0, 
          le=10.0, 
          description="Minimum base CVSS score (default: 9.0 for CRITICAL)."
      )
      limit: int = Field(
          10, 
          ge=1, 
          le=50, 
          description="Number of records to retrieve (default: 10)."
      )
  ```

### 5.4. `get_top_kevs`
Fetch actively exploited vulnerabilities from the CISA KEV catalog, ordered either by recent addition or by EPSS threat probability.

* **Tool Name:** `get_top_kevs`
* **Input Schema:**
  ```python
  class GetTopKevsInput(BaseModel):
      limit: int = Field(
          10, 
          ge=1, 
          le=50, 
          description="Number of KEV items to return (default: 10, max: 50)."
      )
      sort_by: Literal["date_added", "epss_score"] = Field(
          "date_added", 
          description="Sort order: 'date_added' for newest emergency additions, or 'epss_score' for highest probability of immediate exploitation."
      )
  ```

### 5.5. `get_epss_score`
Query specific EPSS real-time exploitation probability scores for one or more CVEs.

* **Tool Name:** `get_epss_score`
* **Input Schema:**
  ```python
  class GetEpssScoreInput(BaseModel):
      cve_ids: List[str] = Field(
          ..., 
          min_items=1, 
          max_items=50, 
          description="List of CVE identifiers (e.g., ['CVE-2023-34362', 'CVE-2024-21887'])."
      )
  ```

---

## 6. Database Schema & Architecture (`.data/vulnscan.db`)

The SQLite database must preserve existing data while introducing optimized tables, virtual full-text search (FTS5), and indexing:

```sql
-- Core CVE Registry (Reuses and extends historical vulnscan.db data)
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cvss_v4_score REAL,
    cvss_v4_vector TEXT,
    severity TEXT, -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    published_date TEXT NOT NULL, -- ISO-8601 string
    last_modified_date TEXT NOT NULL,
    cwe_ids TEXT, -- JSON array: '["CWE-79", "CWE-89"]'
    references_json TEXT, -- JSON array of URLs
    cpe_match_json TEXT, -- JSON array of affected CPE patterns
    raw_nvd_json TEXT
);

-- Full Text Search Index for high-performance component and keyword matching
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    cve_id,
    description,
    cpe_match_json,
    content='cves',
    content_rowid='rowid'
);

-- Triggers to maintain FTS5 index sync with cves table
CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cves_fts(rowid, cve_id, description, cpe_match_json) 
    VALUES (new.rowid, new.cve_id, new.description, new.cpe_match_json);
END;

CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, cpe_match_json) 
    VALUES ('delete', old.rowid, old.cve_id, old.description, old.cpe_match_json);
END;

CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, cve_id, description, cpe_match_json) 
    VALUES ('delete', old.rowid, old.cve_id, old.description, old.cpe_match_json);
    INSERT INTO cves_fts(rowid, cve_id, description, cpe_match_json) 
    VALUES (new.rowid, new.cve_id, new.description, new.cpe_match_json);
END;

-- CISA Known Exploited Vulnerabilities Catalog
CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added TEXT NOT NULL,
    short_description TEXT,
    required_action TEXT,
    due_date TEXT,
    known_ransomware_campaign_use TEXT,
    notes TEXT,
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
);

-- FIRST.org EPSS Probabilistic Scores Cache
CREATE TABLE IF NOT EXISTS epss_cache (
    cve_id TEXT PRIMARY KEY,
    epss_score REAL NOT NULL,
    percentile REAL NOT NULL,
    date_recorded TEXT NOT NULL,
    last_fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- MITRE ATT&CK Mapping Table
CREATE TABLE IF NOT EXISTS mitre_attack_mapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    tactic_id TEXT NOT NULL,       -- e.g., 'TA0001'
    tactic_name TEXT NOT NULL,     -- e.g., 'Initial Access'
    technique_id TEXT NOT NULL,    -- e.g., 'T1190'
    technique_name TEXT NOT NULL,  -- e.g., 'Exploit Public-Facing Application'
    capec_id TEXT,
    FOREIGN KEY(cve_id) REFERENCES cves(cve_id)
);

-- Sync Metadata & State Tracking
CREATE TABLE IF NOT EXISTS sync_state (
    source_name TEXT PRIMARY KEY,
    last_sync_timestamp TEXT NOT NULL,
    records_synced INTEGER DEFAULT 0,
    sync_status TEXT DEFAULT 'SUCCESS',
    error_message TEXT
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_pub_date ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_mod_date ON cves(last_modified_date);
CREATE INDEX IF NOT EXISTS idx_kev_date_added ON cisa_kev(date_added);
CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_cache(epss_score DESC);
CREATE INDEX IF NOT EXISTS idx_mitre_cve ON mitre_attack_mapping(cve_id);
```

---

## 7. Directory Structure & Project Layout

```
vulnscan-mcp/
├── .data/
│   └── vulnscan.db             # Persistent SQLite database (existing historical data preserved)
├── .env.example                # Environment variables configured for Port 8001
├── .gitignore
├── Dockerfile                  # Multi-stage container using uv (Exposes Port 8001)
├── docker-compose.yml          # Port 8001 mapping & volumes
├── pyproject.toml              # UV / PEP 621 project configuration
├── README.md                   # Setup and AI integration guide
├── strategy.md                 # Antigravity IDE roadmap & implementation spec
└── src/
    └── vulnscan/
        ├── __init__.py
        ├── main.py             # Server entry point (FastMCP CLI, stdio/SSE handlers on 8001)
        ├── config.py           # Pydantic Settings (Port 8001, API keys, sync intervals)
        ├── scheduler.py        # APScheduler async background task manager
        ├── database/
        │   ├── __init__.py
        │   ├── connection.py   # Async SQLite pool (aiosqlite) with WAL mode
        │   ├── schema.py       # Table creation, FTS5 triggers, migrations
        │   └── queries.py      # Core query builders (FTS5, KEV join, severity filtering)
        ├── clients/
        │   ├── __init__.py
        │   ├── base.py         # Async HTTP client base with retry & rate limiting
        │   ├── nvd_client.py   # NVD 2.0 API client (pagination, API key auth)
        │   ├── cisa_client.py  # CISA KEV feed downloader and parser
        │   ├── epss_client.py  # FIRST.org EPSS client (batched queries)
        │   └── mitre_client.py # MITRE ATT&CK mapper & data loader
        ├── services/
        │   ├── __init__.py
        │   ├── sync_service.py # Periodic sync workers (NVD delta, CISA KEV, EPSS)
        │   └── search_service.py# Data fusion engine (merges NVD + KEV + EPSS + ATT&CK)
        └── tools/
            ├── __init__.py
            ├── search_tools.py # search_vulnerabilities implementation
            ├── cve_tools.py    # get_cve_details & get_latest_critical_cves
            └── threat_tools.py # get_top_kevs & get_epss_score
```

---

## 8. Technology Stack & `uv` Configuration

### 8.1. `pyproject.toml`
```toml
[project]
name = "vulnscan-mcp"
version = "0.1.0"
description = "Vulnerability Intelligence MCP Server with Automated Ingestion"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "mcp[cli]>=1.2.0",
    "pydantic>=2.7.0",
    "pydantic-settings>=2.2.0",
    "httpx[http2]>=0.27.0",
    "aiosqlite>=0.20.0",
    "tenacity>=8.3.0",
    "apscheduler>=3.10.4",
    "python-dotenv>=1.0.1",
    "uvicorn>=0.30.0",
]

[project.scripts]
vulnscan-mcp = "vulnscan.main:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.uv]
dev-dependencies = [
    "pytest>=8.2.0",
    "pytest-asyncio>=0.23.0",
    "ruff>=0.4.0",
]
```

---

## 9. Containerization & Docker Deployment (Port 8001)

### 9.1. Multi-Stage `Dockerfile`
```dockerfile
# Stage 1: Build virtual environment with uv
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1     UV_LINK_MODE=copy

# Install dependencies without copying source for cache reuse
RUN --mount=type=cache,target=/root/.cache/uv     --mount=type=bind,source=uv.lock,target=uv.lock     --mount=type=bind,source=pyproject.toml,target=pyproject.toml     uv sync --frozen --no-install-project --no-dev

# Copy source and install project
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv     uv sync --frozen --no-dev

# Stage 2: Final minimal runtime image
FROM python:3.12-slim-bookworm

WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -u 10001 appuser

# Copy virtualenv and source
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --chown=appuser:appuser src/ /app/src/

# Prepare persistent data directory
RUN mkdir -p /app/.data && chown -R appuser:appuser /app/.data

ENV PATH="/app/.venv/bin:$PATH"     PYTHONUNBUFFERED=1     DATA_DIR="/app/.data"

USER appuser

# Expose Port 8001 (Port 8000 is occupied by another app)
EXPOSE 8001

ENTRYPOINT ["python", "-m", "vulnscan.main"]
CMD ["--transport", "sse", "--port", "8001"]
```

### 9.2. `docker-compose.yml`
```yaml
version: '3.8'

services:
  vulnscan-mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: vulnscan-mcp
    restart: unless-stopped
    ports:
      - "8001:8001" # Port 8001 mapped for SSE / HTTP transport mode
    volumes:
      - ./.data:/app/.data:rw       # Persistent SQLite storage
      - ./.env:/app/.env:ro         # API keys & configurations
    environment:
      - NVD_API_KEY=${NVD_API_KEY}
      - DATA_DIR=/app/.data
      - MCP_TRANSPORT=sse
      - MCP_PORT=8001
      - MCP_HOST=0.0.0.0
      - NVD_SYNC_INTERVAL_HOURS=2
      - KEV_SYNC_INTERVAL_HOURS=12
      - EPSS_SYNC_INTERVAL_HOURS=24
      - LOG_LEVEL=INFO
```

### 9.3. Environment Configuration (`.env.example`)
```env
# NIST NVD API Key (Obtain from https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=your_nvd_api_key_here

# MCP Server Settings (Port 8001)
MCP_TRANSPORT=sse            # 'stdio' for CLI/desktop agents, 'sse' for network agents
MCP_HOST=0.0.0.0
MCP_PORT=8001

# Database & Cache Settings
DATA_DIR=./.data
DB_NAME=vulnscan.db
LOG_LEVEL=INFO

# Automated Periodic Synchronization Cadence (in Hours)
NVD_SYNC_INTERVAL_HOURS=2    # Continuous delta sync from NVD 2.0
KEV_SYNC_INTERVAL_HOURS=12   # CISA KEV catalog check
EPSS_SYNC_INTERVAL_HOURS=24  # Batch EPSS enrichment
```

---

## 10. AI Client Integration Profiles (Port 8001)

### 10.1. Claude Desktop / Claude Code (`claude_desktop_config.json`)
For direct local execution:
```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "uv",
      "args": [
        "--directory", "/path/to/vulnscan-mcp",
        "run",
        "vulnscan-mcp",
        "--transport", "stdio"
      ],
      "env": {
        "NVD_API_KEY": "your_key_here"
      }
    }
  }
}
```

Or via Docker (stdio mode):
```json
{
  "mcpServers": {
    "vulnscan": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/path/to/vulnscan-mcp/.data:/app/.data",
        "-e", "NVD_API_KEY=your_key_here",
        "vulnscan-mcp:latest",
        "--transport", "stdio"
      ]
    }
  }
}
```

### 10.2. Cursor / OpenAI Agent / Remote Tools (SSE Mode on Port 8001)
Run container in SSE mode:
```bash
docker run -d -p 8001:8001 -v $(pwd)/.data:/app/.data --env-file .env vulnscan-mcp:latest --transport sse --port 8001
```
Connect your AI client to:
```
http://localhost:8001/sse
```

---

## 11. Antigravity IDE Step-by-Step Implementation Roadmap

### Phase 1: Project Initialization & Dependency Setup
1. Initialize repository with `uv init --lib vulnscan-mcp`.
2. Generate `pyproject.toml` with `APScheduler`, `mcp`, `httpx`, `aiosqlite`, and `pydantic`.
3. Configure `.env.example` with `MCP_PORT=8001` and periodic interval definitions.

### Phase 2: Database Schema & Migration
1. Validate existing `.data/vulnscan.db` historical records.
2. Execute migration script to ensure `cisa_kev`, `epss_cache`, `mitre_attack_mapping`, and `sync_state` tables exist.
3. Build the FTS5 virtual table `cves_fts` with synchronization triggers.
4. Enable WAL mode (`PRAGMA journal_mode=WAL;`) so background sync writes do not block agent read queries.

### Phase 3: External API Ingestion Clients
1. Implement `nvd_client.py` using `httpx.AsyncClient` with API key headers and exponential backoff retry.
2. Implement `cisa_client.py` to stream and parse the CISA KEV JSON feed.
3. Implement `epss_client.py` for single and batched EPSS score lookups.
4. Implement `mitre_client.py` with embedded ATT&CK tactic/technique mapping.

### Phase 4: Periodic Synchronization Engine (`scheduler.py` & `sync_service.py`)
1. Implement `sync_service.py` to handle incremental NVD deltas via `lastModStartDate`.
2. Implement CISA KEV and EPSS batch update procedures in `sync_service.py`.
3. Wire `APScheduler` in `scheduler.py` to launch background sync jobs at startup alongside the MCP server.

### Phase 5: Core MCP Server & Tool Handlers
1. Scaffold FastMCP server in `src/vulnscan/main.py`.
2. Implement `search_vulnerabilities`, `get_cve_details`, `get_latest_critical_cves`, `get_top_kevs`, and `get_epss_score`.
3. Support both `stdio` and `sse` transport types, setting default port to `8001`.

### Phase 6: Containerization & Verification
1. Author multi-stage `Dockerfile` and `docker-compose.yml` mapped to port `8001`.
2. Verify startup: Confirm periodic jobs initialize in the background without blocking the MCP SSE endpoint.
3. Validate MCP handshake on `http://localhost:8001/sse` using MCP Inspector:
   ```bash
   npx @modelcontextprotocol/inspector
   ```
