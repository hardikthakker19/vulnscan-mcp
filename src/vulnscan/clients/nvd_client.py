"""NVD 2.0 API client with pagination and delta fetching."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from vulnscan.clients.base import BaseClient
from vulnscan.config import get_settings

logger = logging.getLogger(__name__)


def _parse_nvd_cve(vuln: dict[str, Any]) -> dict[str, Any]:
    """Parse a raw NVD 2.0 CVE item into our normalized schema."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")

    # Extract description (English preferred)
    descriptions = cve.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # Extract CVSS v3.1 metrics
    cvss_v3_score = None
    cvss_v3_vector = None
    severity = None
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key, [])
        if metric_list:
            primary = metric_list[0]
            cvss_data = primary.get("cvssData", {})
            cvss_v3_score = cvss_data.get("baseScore")
            cvss_v3_vector = cvss_data.get("vectorString")
            severity = cvss_data.get("baseSeverity", "").upper()
            break

    # Extract CVSS v4.0 metrics
    cvss_v4_score = None
    cvss_v4_vector = None
    v4_metrics = metrics.get("cvssMetricV40", [])
    if v4_metrics:
        v4_primary = v4_metrics[0]
        v4_data = v4_primary.get("cvssData", {})
        cvss_v4_score = v4_data.get("baseScore")
        cvss_v4_vector = v4_data.get("vectorString")

    # Fallback severity from v2 if no v3/v4
    if not severity:
        v2_metrics = metrics.get("cvssMetricV2", [])
        if v2_metrics:
            severity = v2_metrics[0].get("baseSeverity", "").upper()

    # Extract CWE IDs
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)

    # Extract references
    references = []
    for ref in cve.get("references", []):
        references.append(ref.get("url", ""))

    # Extract CPE match patterns with version bounds
    cpe_matches = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    criteria = match.get("criteria", "")
                    entry: dict[str, Any] = {"criteria": criteria}
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        entry["vendor"] = parts[3]
                        entry["product"] = parts[4]
                        if len(parts) > 5 and parts[5] not in ("*", "-"):
                            entry["version"] = parts[5]
                    for k in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    ):
                        if match.get(k):
                            entry[k] = match[k]
                    cpe_matches.append(entry)

    published = cve.get("published", "")
    modified = cve.get("lastModified", "")

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v4_score": cvss_v4_score,
        "cvss_v4_vector": cvss_v4_vector,
        "severity": severity or None,
        "published_date": published,
        "last_modified_date": modified,
        "cwe_ids": json.dumps(cwe_ids) if cwe_ids else None,
        "references_json": json.dumps(references) if references else None,
        "cpe_match_json": json.dumps(cpe_matches) if cpe_matches else None,
        "raw_nvd_json": json.dumps(vuln),
    }


class NVDClient(BaseClient):
    """Client for the NIST NVD 2.0 API."""

    def __init__(self):
        settings = get_settings()
        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        super().__init__(
            base_url=settings.nvd_api_base_url,
            headers=headers,
            timeout=60.0,
        )
        self._has_api_key = bool(settings.nvd_api_key)

    async def fetch_cves_delta(
        self,
        last_mod_start: str,
        last_mod_end: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch CVEs modified between two timestamps (delta sync).

        Args:
            last_mod_start: ISO-8601 start timestamp.
            last_mod_end: ISO-8601 end timestamp (default: now).

        Returns:
            List of parsed CVE dictionaries.
        """
        if not last_mod_end:
            last_mod_end = datetime.now(UTC).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

        all_cves: list[dict[str, Any]] = []
        start_index = 0
        results_per_page = 2000
        total_results = None

        logger.info(
            f"NVD delta fetch: {last_mod_start} → {last_mod_end}"
        )

        while True:
            params = {
                "lastModStartDate": last_mod_start,
                "lastModEndDate": last_mod_end,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }

            data = await self.get(params=params)

            if total_results is None:
                total_results = data.get("totalResults", 0)
                logger.info(f"NVD reports {total_results} total results")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for vuln in vulnerabilities:
                parsed = _parse_nvd_cve(vuln)
                if parsed["cve_id"]:
                    all_cves.append(parsed)

            start_index += len(vulnerabilities)

            if start_index >= total_results:
                break

            logger.info(
                f"NVD pagination: fetched {start_index}/{total_results}"
            )

        logger.info(f"NVD delta fetch complete: {len(all_cves)} CVEs")
        return all_cves

    async def search_cves(
        self,
        keyword: str | None = None,
        cve_id: str | None = None,
        results_per_page: int = 20,
    ) -> list[dict[str, Any]]:
        """Search NVD for CVEs by keyword or specific CVE ID.

        Used for on-demand API lookups when local data is insufficient.
        """
        params: dict[str, Any] = {"resultsPerPage": results_per_page}

        if cve_id:
            params["cveId"] = cve_id
        elif keyword:
            params["keywordSearch"] = keyword

        data = await self.get(params=params)
        vulnerabilities = data.get("vulnerabilities", [])

        return [
            _parse_nvd_cve(vuln)
            for vuln in vulnerabilities
            if _parse_nvd_cve(vuln)["cve_id"]
        ]
