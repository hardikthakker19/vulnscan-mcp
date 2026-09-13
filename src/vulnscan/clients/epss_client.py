"""FIRST.org EPSS (Exploit Prediction Scoring System) client."""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.clients.base import BaseClient
from vulnscan.config import get_settings

logger = logging.getLogger(__name__)


class EPSSClient(BaseClient):
    """Client for the FIRST.org EPSS API with batch support."""

    def __init__(self):
        settings = get_settings()
        super().__init__(
            base_url=settings.epss_api_base_url,
            timeout=30.0,
        )

    async def get_scores(
        self, cve_ids: list[str]
    ) -> list[dict[str, Any]]:
        """Fetch EPSS scores for a list of CVE IDs.

        Supports batch queries up to 100 CVEs per request.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            List of dicts with cve_id, epss_score, percentile, date_recorded.
        """
        if not cve_ids:
            return []

        results: list[dict[str, Any]] = []

        # Split into batches of 100
        batch_size = 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            batch_str = ",".join(batch)

            logger.debug(
                f"EPSS batch query: {len(batch)} CVEs "
                f"(batch {i // batch_size + 1})"
            )

            try:
                data = await self.get(params={"cve": batch_str})
                epss_data = data.get("data", [])

                for item in epss_data:
                    results.append(
                        {
                            "cve_id": item.get("cve", ""),
                            "epss_score": float(item.get("epss", 0.0)),
                            "percentile": float(
                                item.get("percentile", 0.0)
                            ),
                            "date_recorded": item.get("date", ""),
                        }
                    )
            except Exception as e:
                logger.warning(
                    f"EPSS batch query failed for {len(batch)} CVEs: {e}"
                )
                continue

        logger.info(f"EPSS: fetched scores for {len(results)} CVEs")
        return results

    async def get_single_score(
        self, cve_id: str
    ) -> dict[str, Any] | None:
        """Fetch EPSS score for a single CVE ID.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dict with epss_score, percentile, date_recorded or None.
        """
        results = await self.get_scores([cve_id])
        return results[0] if results else None
