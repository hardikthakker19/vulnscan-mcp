"""get_top_kevs and get_epss_score MCP tool implementations."""

from __future__ import annotations

import json
import logging
import re
from typing import Literal

from pydantic import BaseModel, Field

from vulnscan.services.search_service import (
    get_epss_scores as _get_epss,
)
from vulnscan.services.search_service import (
    get_top_kevs as _get_kevs,
)

logger = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class GetTopKevsInput(BaseModel):
    """Input schema for the get_top_kevs tool."""

    limit: int = Field(
        10,
        ge=1,
        le=50,
        description="Number of KEV items to return (default: 10, max: 50).",
    )
    sort_by: Literal["date_added", "epss_score"] = Field(
        "date_added",
        description=(
            "Sort order: 'date_added' for newest emergency additions, "
            "or 'epss_score' for highest probability of immediate exploitation."
        ),
    )


class GetEpssScoreInput(BaseModel):
    """Input schema for the get_epss_score tool."""

    cve_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of CVE identifiers (e.g., ['CVE-2023-34362', 'CVE-2024-21887']).",
    )


async def get_top_kevs_handler(
    limit: int = 10,
    sort_by: str = "date_added",
) -> str:
    """Fetch actively exploited vulnerabilities from the CISA KEV catalog."""
    if sort_by not in ("date_added", "epss_score"):
        sort_by = "date_added"

    result = await _get_kevs(limit=limit, sort_by=sort_by)
    return json.dumps(result, indent=2, default=str)


async def get_epss_score_handler(cve_ids: list[str]) -> str:
    """Query EPSS real-time exploitation probability scores for one or more CVEs."""
    # Validate all CVE IDs
    invalid = [cid for cid in cve_ids if not CVE_PATTERN.match(cid.upper().strip())]
    if invalid:
        return json.dumps({
            "error": f"Invalid CVE ID(s): {invalid}. Expected format: CVE-YYYY-NNNNN"
        })

    cleaned = [cid.upper().strip() for cid in cve_ids]
    result = await _get_epss(cleaned)
    return json.dumps(result, indent=2, default=str)
