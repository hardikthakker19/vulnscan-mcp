"""Periodic sync workers for NVD delta, CISA KEV, and EPSS enrichment."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnscan.clients.cisa_client import CISAClient
from vulnscan.clients.epss_client import EPSSClient
from vulnscan.clients.mitre_client import MITREClient
from vulnscan.clients.nvd_client import NVDClient
from vulnscan.database import queries
from vulnscan.database.connection import get_connection

logger = logging.getLogger(__name__)

_mitre_client = MITREClient()


async def sync_nvd_delta() -> None:
    """Incremental NVD CVE sync using lastModStartDate delta tracking."""
    logger.info("Starting NVD delta sync...")

    try:
        # Get last sync timestamp (NVD API requires date window <= 120 days)
        state = await queries.get_sync_state("NVD")
        last_sync = state["last_sync_timestamp"] if state else None
        
        now_dt = datetime.now(UTC)
        now = now_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        if not last_sync or last_sync.startswith("1970"):
            # Default to last 7 days for initial delta sync
            last_sync = (now_dt - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        else:
            try:
                # Parse and clamp to maximum 119 days
                last_sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                if (now_dt - last_sync_dt).days > 119:
                    last_sync = (now_dt - timedelta(days=119)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except Exception:
                last_sync = (now_dt - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Update state to RUNNING
        await queries.update_sync_state("NVD", last_sync, 0, "RUNNING")

        client = NVDClient()
        try:
            cves = await client.fetch_cves_delta(last_sync, now)

            if cves:
                count = await queries.upsert_cves(cves)

                # Enrich with MITRE ATT&CK mappings
                await _enrich_attack_mappings(cves)

                logger.info(f"NVD sync: upserted {count} CVEs")
                await queries.update_sync_state("NVD", now, count, "SUCCESS")
            else:
                logger.info("NVD sync: no new or modified CVEs")
                await queries.update_sync_state("NVD", now, 0, "SUCCESS")
        finally:
            await client.close()

    except Exception as e:
        logger.error(f"NVD sync failed: {e}", exc_info=True)
        await queries.update_sync_state(
            "NVD",
            datetime.now(UTC).isoformat(),
            0,
            "FAILED",
            str(e),
        )


async def sync_cisa_kev() -> None:
    """Full CISA KEV catalog download and upsert."""
    logger.info("Starting CISA KEV sync...")

    try:
        await queries.update_sync_state(
            "CISA_KEV",
            datetime.now(UTC).isoformat(),
            0,
            "RUNNING",
        )

        client = CISAClient()
        try:
            entries = await client.fetch_kev_catalog()

            if entries:
                count = await queries.upsert_kev_entries(entries)
                now = datetime.now(UTC).isoformat()
                logger.info(f"CISA KEV sync: upserted {count} entries")
                await queries.update_sync_state("CISA_KEV", now, count, "SUCCESS")
            else:
                logger.warning("CISA KEV sync: no entries retrieved")
                await queries.update_sync_state(
                    "CISA_KEV",
                    datetime.now(UTC).isoformat(),
                    0,
                    "SUCCESS",
                )
        finally:
            await client.close()

    except Exception as e:
        logger.error(f"CISA KEV sync failed: {e}", exc_info=True)
        await queries.update_sync_state(
            "CISA_KEV",
            datetime.now(UTC).isoformat(),
            0,
            "FAILED",
            str(e),
        )


async def sync_epss_scores() -> None:
    """Batch EPSS enrichment for KEV CVEs and recent critical CVEs."""
    logger.info("Starting EPSS batch enrichment...")

    try:
        await queries.update_sync_state(
            "EPSS",
            datetime.now(UTC).isoformat(),
            0,
            "RUNNING",
        )

        conn = await get_connection()

        # Collect CVE IDs: all KEV entries + critical CVEs from last 30 days
        cursor = await conn.execute("SELECT cve_id FROM cisa_kev")
        kev_rows = await cursor.fetchall()
        kev_ids = {row[0] for row in kev_rows}

        cursor = await conn.execute(
            """SELECT cve_id FROM cves
               WHERE severity = 'CRITICAL'
                 AND published_date >= datetime('now', '-30 days')"""
        )
        critical_rows = await cursor.fetchall()
        critical_ids = {row[0] for row in critical_rows}

        all_cve_ids = list(kev_ids | critical_ids)

        if not all_cve_ids:
            logger.info("EPSS sync: no CVEs to enrich")
            await queries.update_sync_state(
                "EPSS",
                datetime.now(UTC).isoformat(),
                0,
                "SUCCESS",
            )
            return

        logger.info(f"EPSS sync: enriching {len(all_cve_ids)} CVEs")

        client = EPSSClient()
        try:
            # Process in batches of 50
            total_count = 0
            for i in range(0, len(all_cve_ids), 50):
                batch = all_cve_ids[i : i + 50]
                scores = await client.get_scores(batch)
                if scores:
                    count = await queries.upsert_epss_scores(scores)
                    total_count += count
        finally:
            await client.close()

        now = datetime.now(UTC).isoformat()
        logger.info(f"EPSS sync: enriched {total_count} scores")
        await queries.update_sync_state("EPSS", now, total_count, "SUCCESS")

    except Exception as e:
        logger.error(f"EPSS sync failed: {e}", exc_info=True)
        await queries.update_sync_state(
            "EPSS",
            datetime.now(UTC).isoformat(),
            0,
            "FAILED",
            str(e),
        )


async def _enrich_attack_mappings(cves: list[dict[str, Any]]) -> None:
    """Enrich CVEs with MITRE ATT&CK mappings based on their CWE IDs."""
    import json

    conn = await get_connection()

    for cve in cves:
        cwe_ids_raw = cve.get("cwe_ids")
        if not cwe_ids_raw:
            continue

        try:
            cwe_ids = json.loads(cwe_ids_raw)
        except (json.JSONDecodeError, TypeError):
            continue

        if not cwe_ids:
            continue

        mappings = _mitre_client.get_attack_mappings(cwe_ids)
        if not mappings:
            continue

        cve_id = cve["cve_id"]

        # Delete existing mappings and reinsert
        await conn.execute(
            "DELETE FROM mitre_attack_mapping WHERE cve_id = ?",
            (cve_id,),
        )

        for m in mappings:
            await conn.execute(
                """INSERT INTO mitre_attack_mapping
                   (cve_id, tactic_id, tactic_name, technique_id, technique_name, capec_id)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    cve_id,
                    m["tactic_id"],
                    m["tactic_name"],
                    m["technique_id"],
                    m["technique_name"],
                    m.get("capec_id"),
                ),
            )

    await conn.commit()
