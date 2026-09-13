"""FastMCP server entry point for vulnscan-mcp."""

from __future__ import annotations

import asyncio
import logging
import sys

from mcp.server.mcpserver import MCPServer

from vulnscan.config import get_settings
from vulnscan.database.connection import close_connection, init_connection
from vulnscan.database.schema import initialize_schema
from vulnscan.scheduler import start_scheduler, stop_scheduler
from vulnscan.tools.cve_tools import (
    get_cve_details_handler,
    get_latest_critical_handler,
)
from vulnscan.tools.search_tools import search_vulnerabilities_handler
from vulnscan.tools.threat_tools import get_epss_score_handler, get_top_kevs_handler

# ─── Logging Setup ──────────────────────────────────────────────────────────

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("vulnscan")

# ─── FastMCP Server ─────────────────────────────────────────────────────────

mcp = MCPServer(
    "vulnscan-mcp",
    instructions=(
        "Vulnerability Intelligence MCP Server — provides real-time, correlated "
        "vulnerability intelligence from NVD, CISA KEV, FIRST EPSS, and MITRE ATT&CK."
    ),
)


# ─── Lifecycle Hooks ────────────────────────────────────────────────────────

@mcp.tool()
async def search_vulnerabilities(
    keyword: str | None = None,
    severity: str | None = None,
    pubStartDate: str | None = None,
    pubEndDate: str | None = None,
    hasKev: bool | None = False,
    limit: int = 20,
) -> str:
    """Search and filter vulnerabilities across local storage and synchronized feeds.

    Search by keyword (CVE ID, component, vendor, description), filter by severity
    (LOW/MEDIUM/HIGH/CRITICAL), publication date range, and CISA KEV status.

    Args:
        keyword: Search term matching CVE ID, component, vendor, or description.
        severity: Filter by CVSS severity: LOW, MEDIUM, HIGH, or CRITICAL.
        pubStartDate: Start publication date in ISO-8601 format (e.g., '2024-01-01').
        pubEndDate: End publication date in ISO-8601 format (e.g., '2024-12-31').
        hasKev: If True, filters for CVEs in the CISA Known Exploited Vulnerabilities catalog.
        limit: Maximum records to return (1-50, default: 20).
    """
    return await search_vulnerabilities_handler(
        keyword=keyword,
        severity=severity,
        pubStartDate=pubStartDate,
        pubEndDate=pubEndDate,
        hasKev=hasKev,
        limit=limit,
    )


@mcp.tool()
async def get_cve_details(cve_id: str) -> str:
    """Retrieve a comprehensive, deeply enriched 360-degree security profile for a CVE.

    Returns NVD CVSS scores, CISA KEV active exploitation status, FIRST.org EPSS
    exploitation probability, MITRE ATT&CK tactics/techniques, and risk assessment.

    Args:
        cve_id: Standardized CVE identifier (e.g., 'CVE-2021-44228', 'CVE-2024-3094').
    """
    return await get_cve_details_handler(cve_id=cve_id)


@mcp.tool()
async def get_latest_critical_cves(
    days: int = 7,
    min_cvss: float = 9.0,
    limit: int = 10,
) -> str:
    """Fetch newly published critical vulnerabilities from the synchronized database.

    Args:
        days: Past calendar days to search (1-90, default: 7).
        min_cvss: Minimum base CVSS score threshold (7.0-10.0, default: 9.0).
        limit: Number of records to retrieve (1-50, default: 10).
    """
    return await get_latest_critical_handler(
        days=days,
        min_cvss=min_cvss,
        limit=limit,
    )


@mcp.tool()
async def get_top_kevs(
    limit: int = 10,
    sort_by: str = "date_added",
) -> str:
    """Fetch actively exploited vulnerabilities from the CISA KEV catalog.

    Returns KEV entries ordered by recent addition or EPSS threat probability.

    Args:
        limit: Number of KEV items to return (1-50, default: 10).
        sort_by: Sort order — 'date_added' for newest or 'epss_score' for highest exploitation probability.
    """
    return await get_top_kevs_handler(limit=limit, sort_by=sort_by)


@mcp.tool()
async def get_epss_score(cve_ids: list[str]) -> str:
    """Query EPSS real-time exploitation probability scores for one or more CVEs.

    Checks local cache first, then fetches from FIRST.org EPSS API for cache misses.

    Args:
        cve_ids: List of CVE identifiers (e.g., ['CVE-2023-34362', 'CVE-2024-21887']).
    """
    return await get_epss_score_handler(cve_ids=cve_ids)


from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import (
    StreamableHTTPASGIApp,
    StreamableHTTPSessionManager,
)
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

# ─── Server Initialization ─────────────────────────────────────────────────

async def _startup() -> None:
    """Initialize database and start background sync scheduler."""
    logger.info("vulnscan-mcp starting up...")

    # Initialize database connection and schema
    await init_connection()
    await initialize_schema()

    # Start background sync scheduler
    await start_scheduler()

    logger.info("vulnscan-mcp ready")


async def _shutdown() -> None:
    """Clean shutdown of scheduler and database."""
    logger.info("vulnscan-mcp shutting down...")
    await stop_scheduler()
    await close_connection()
    logger.info("vulnscan-mcp stopped")


def create_unified_app() -> Starlette:
    """Create a unified Starlette application supporting both SSE and Streamable-HTTP MCP transports,
    plus health-check landing endpoints and CORS support."""
    sse = SseServerTransport("/messages/")
    session_manager = StreamableHTTPSessionManager(app=mcp._lowlevel_server)
    stream_app = StreamableHTTPASGIApp(session_manager)

    class HybridEndpoint:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "http":
                method = scope["method"]
                if method in ("GET", "HEAD"):
                    path = scope.get("path", "")
                    accept = dict(scope.get("headers", [])).get(b"accept", b"").decode()
                    if path == "/" and "text/event-stream" not in accept:
                        resp = JSONResponse({
                            "status": "ok",
                            "name": "vulnscan-mcp",
                            "version": "0.1.0",
                            "description": "Vulnerability Intelligence MCP Server",
                            "transports": ["sse", "streamable-http"],
                            "endpoints": ["/sse", "/mcp", "/messages"],
                        })
                        await resp(scope, receive, send)
                        return

                    async with sse.connect_sse(scope, receive, send) as streams:
                        await mcp._lowlevel_server.run(
                            streams[0], streams[1], mcp._lowlevel_server.create_initialization_options()
                        )
                    return
                elif method == "POST":
                    query_string = scope.get("query_string", b"").decode()
                    if "session_id=" in query_string:
                        await sse.handle_post_message(scope, receive, send)
                    else:
                        await stream_app(scope, receive, send)
                    return
                elif method == "DELETE":
                    await stream_app(scope, receive, send)
                    return

            resp = Response("Method Not Allowed", status_code=405)
            await resp(scope, receive, send)

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["*"],
        )
    ]

    async def well_known_oauth(request: Request) -> Response:
        return Response(status_code=404)

    routes = [
        Route("/sse", endpoint=HybridEndpoint()),
        Route("/messages", endpoint=sse.handle_post_message),
        Mount("/messages", app=sse.handle_post_message),
        Route("/mcp", endpoint=stream_app),
        Route("/.well-known/oauth-protected-resource/{path:path}", endpoint=well_known_oauth),
        Route("/.well-known/oauth-protected-resource", endpoint=well_known_oauth),
        Route("/", endpoint=HybridEndpoint()),
    ]

    @asynccontextmanager
    async def app_lifespan(app: Starlette) -> AsyncGenerator[None, None]:
        await _startup()
        try:
            async with session_manager.run():
                yield
        finally:
            await _shutdown()

    return Starlette(
        debug=settings.log_level.upper() == "DEBUG",
        routes=routes,
        middleware=middleware,
        lifespan=app_lifespan,
    )


def main() -> None:
    """Main entry point for the vulnscan-mcp server."""
    import argparse

    parser = argparse.ArgumentParser(description="vulnscan-mcp server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http", "streamable-http"],
        default=settings.mcp_transport,
        help="Transport mode (stdio, or sse/http for network server)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.mcp_port,
        help="Port for network transport (default: 8001)",
    )
    parser.add_argument(
        "--host",
        default=settings.mcp_host,
        help="Host for network transport (default: 0.0.0.0)",
    )

    args = parser.parse_args()

    if args.transport == "stdio":
        asyncio.run(_startup())
        try:
            logger.info("Starting MCP server — transport=stdio")
            mcp.run(transport="stdio")
        finally:
            asyncio.run(_shutdown())
    else:
        import uvicorn

        logger.info(f"Starting unified MCP server (SSE + Streamable-HTTP) on {args.host}:{args.port}")
        app = create_unified_app()
        config = uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            log_level=settings.log_level.lower(),
        )
        server = uvicorn.Server(config)
        server.run()


if __name__ == "__main__":
    main()
