"""CISA Known Exploited Vulnerabilities (KEV) feed client."""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.clients.base import BaseClient
from vulnscan.config import get_settings

logger = logging.getLogger(__name__)


def _parse_kev_entry(vuln: dict[str, Any]) -> dict[str, Any]:
    """Parse a CISA KEV vulnerability entry into our schema."""
    return {
        "cve_id": vuln.get("cveID", ""),
        "vendor_project": vuln.get("vendorProject", ""),
        "product": vuln.get("product", ""),
        "vulnerability_name": vuln.get("vulnerabilityName", ""),
        "date_added": vuln.get("dateAdded", ""),
        "short_description": vuln.get("shortDescription", ""),
        "required_action": vuln.get("requiredAction", ""),
        "due_date": vuln.get("dueDate", ""),
        "known_ransomware_campaign_use": vuln.get(
            "knownRansomwareCampaignUse", "Unknown"
        ),
        "notes": vuln.get("notes", ""),
    }


class CISAClient(BaseClient):
    """Client for the CISA KEV JSON feed."""

    def __init__(self):
        settings = get_settings()
        self._feed_url = settings.kev_catalog_url
        super().__init__(
            base_url="https://www.cisa.gov",
            timeout=60.0,
        )

    async def fetch_kev_catalog(self) -> list[dict[str, Any]]:
        """Download and parse the full CISA KEV catalog.

        Returns:
            List of parsed KEV entry dictionaries.
        """
        logger.info("Fetching CISA KEV catalog...")

        # Request the exact feed URL without trailing slash
        data = await self.get(path=self._feed_url)

        catalog_version = data.get("catalogVersion", "unknown")
        title = data.get("title", "")
        vulnerabilities = data.get("vulnerabilities", [])

        logger.info(
            f"KEV catalog v{catalog_version}: '{title}' — "
            f"{len(vulnerabilities)} entries"
        )

        entries = []
        for vuln in vulnerabilities:
            parsed = _parse_kev_entry(vuln)
            if parsed["cve_id"]:
                entries.append(parsed)

        logger.info(f"Parsed {len(entries)} KEV entries")
        return entries
