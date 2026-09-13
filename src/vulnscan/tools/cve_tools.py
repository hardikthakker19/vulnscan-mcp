"""get_cve_details and get_latest_critical_cves MCP tool implementations."""

from __future__ import annotations

import json
import logging
import re

from pydantic import BaseModel, Field

from vulnscan.services.search_service import (
    get_cve_details as _get_details,
)
from vulnscan.services.search_service import (
    get_latest_critical as _get_critical,
)

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class GetCveDetailsInput(BaseModel):
    """Input schema for the get_cve_details tool."""

    cve_id: str = Field(
        ...,
        description="Standardized CVE identifier (e.g., 'CVE-2021-44228', 'CVE-2024-3094').",
    )


class GetLatestCriticalInput(BaseModel):
    """Input schema for the get_latest_critical_cves tool."""

    days: int = Field(
        7,
        ge=1,
        le=90,
        description="Past calendar days to search (default: 7).",
    )
    min_cvss: float = Field(
        9.0,
        ge=7.0,
        le=10.0,
        description="Minimum base CVSS score (default: 9.0 for CRITICAL).",
    )
    limit: int = Field(
        10,
        ge=1,
        le=50,
        description="Number of records to retrieve (default: 10).",
    )


async def get_cve_details_handler(cve_id: str) -> str:
    """Retrieve a comprehensive, deeply enriched 360-degree security profile for an individual CVE."""
    cve_id = cve_id.upper().strip()

    if not CVE_PATTERN.match(cve_id):
        return json.dumps({
            "error": f"Invalid CVE ID format: '{cve_id}'. Expected format: CVE-YYYY-NNNNN"
        })

    result = await _get_details(cve_id)
    return json.dumps(result, indent=2, default=str)


async def get_latest_critical_handler(
    days: int = 7,
    min_cvss: float = 9.0,
    limit: int = 10,
) -> str:
    """Fetch newly published critical vulnerabilities from the synchronized database."""
    result = await _get_critical(
        days=days,
        min_cvss=min_cvss,
        limit=limit,
    )
    return json.dumps(result, indent=2, default=str)
