"""search_vulnerabilities MCP tool implementation."""

from __future__ import annotations

import json
import logging

from pydantic import BaseModel, Field

from vulnscan.services.search_service import search_vulnerabilities as _search

logger = logging.getLogger(__name__)


class SearchVulnerabilitiesInput(BaseModel):
    """Input schema for the search_vulnerabilities tool."""

    keyword: str | None = Field(
        None,
        description=(
            "Search term matching CVE ID, vulnerable component, vendor, "
            "or description (e.g., 'apache log4j', 'buffer overflow', 'openssl')."
        ),
    )
    severity: str | None = Field(
        None,
        description="Filter by qualitative CVSS v3/v4 severity rating: LOW, MEDIUM, HIGH, CRITICAL.",
    )
    pubStartDate: str | None = Field(
        None,
        description="Start publication date in ISO-8601 format (e.g., '2024-01-01').",
    )
    pubEndDate: str | None = Field(
        None,
        description="End publication date in ISO-8601 format (e.g., '2024-12-31').",
    )
    hasKev: bool | None = Field(
        False,
        description="If True, filters strictly for CVEs in the CISA Known Exploited Vulnerabilities catalog.",
    )
    limit: int = Field(
        20,
        ge=1,
        le=50,
        description="Maximum number of vulnerability records to return (1-50, default: 20).",
    )


async def search_vulnerabilities_handler(
    keyword: str | None = None,
    severity: str | None = None,
    pubStartDate: str | None = None,
    pubEndDate: str | None = None,
    hasKev: bool = False,
    limit: int = 20,
) -> str:
    """Search and filter vulnerabilities across local storage and synchronized feeds."""
    # Validate severity
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if severity and severity.upper() not in valid_severities:
        return json.dumps({
            "error": f"Invalid severity '{severity}'. Must be one of: {', '.join(valid_severities)}"
        })

    result = await _search(
        keyword=keyword,
        severity=severity.upper() if severity else None,
        pub_start_date=pubStartDate,
        pub_end_date=pubEndDate,
        has_kev=hasKev or False,
        limit=limit,
    )

    return json.dumps(result, indent=2, default=str)
