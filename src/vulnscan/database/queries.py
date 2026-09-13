"""Core query builders for FTS5 search, KEV join, severity filtering."""

from __future__ import annotations

import logging
from typing import Any

from vulnscan.database.connection import get_connection

logger = logging.getLogger(__name__)


async def search_cves(
    keyword: str | None = None,
    severity: str | None = None,
    pub_start_date: str | None = None,
    pub_end_date: str | None = None,
    has_kev: bool = False,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Search CVEs using FTS5 and filters, enriched with KEV and EPSS data."""
    conn = await get_connection()

    conditions: list[str] = []
    params: list[Any] = []

    # Build the base query with optional joins
    if keyword:
        # Use FTS5 for keyword search
        base = """
            SELECT c.*, k.date_added AS kev_date_added, k.due_date AS kev_due_date,
                   k.required_action AS kev_required_action,
                   k.known_ransomware_campaign_use AS kev_ransomware,
                   e.epss_score, e.percentile AS epss_percentile
            FROM cves c
            INNER JOIN cves_fts fts ON c.rowid = fts.rowid
            LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
            LEFT JOIN epss_cache e ON c.cve_id = e.cve_id
            WHERE cves_fts MATCH ?
        """
        # Escape special FTS5 characters and create query
        safe_keyword = keyword.replace('"', '""')
        params.append(f'"{safe_keyword}"')
    else:
        base = """
            SELECT c.*, k.date_added AS kev_date_added, k.due_date AS kev_due_date,
                   k.required_action AS kev_required_action,
                   k.known_ransomware_campaign_use AS kev_ransomware,
                   e.epss_score, e.percentile AS epss_percentile
            FROM cves c
            LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
            LEFT JOIN epss_cache e ON c.cve_id = e.cve_id
            WHERE 1=1
        """

    if severity:
        conditions.append("c.severity = ?")
        params.append(severity.upper())

    if pub_start_date:
        conditions.append("c.published_date >= ?")
        params.append(pub_start_date)

    if pub_end_date:
        conditions.append("c.published_date <= ?")
        params.append(pub_end_date)

    if has_kev:
        conditions.append("k.cve_id IS NOT NULL")

    where_clause = ""
    if conditions:
        where_clause = " AND " + " AND ".join(conditions)

    query = f"{base}{where_clause} ORDER BY c.published_date DESC LIMIT ?"
    params.append(limit)

    cursor = await conn.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_cve_by_id(cve_id: str) -> dict[str, Any] | None:
    """Get a single CVE with full enrichment (KEV + EPSS + ATT&CK)."""
    conn = await get_connection()

    query = """
        SELECT c.*, k.date_added AS kev_date_added, k.due_date AS kev_due_date,
               k.vendor_project AS kev_vendor, k.product AS kev_product,
               k.vulnerability_name AS kev_vuln_name,
               k.short_description AS kev_description,
               k.required_action AS kev_required_action,
               k.known_ransomware_campaign_use AS kev_ransomware,
               k.notes AS kev_notes,
               e.epss_score, e.percentile AS epss_percentile,
               e.date_recorded AS epss_date
        FROM cves c
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        LEFT JOIN epss_cache e ON c.cve_id = e.cve_id
        WHERE c.cve_id = ?
    """
    cursor = await conn.execute(query, (cve_id,))
    row = await cursor.fetchone()
    if not row:
        return None

    result = dict(row)

    # Fetch ATT&CK mappings
    attack_cursor = await conn.execute(
        """SELECT tactic_id, tactic_name, technique_id, technique_name, capec_id
           FROM mitre_attack_mapping WHERE cve_id = ?""",
        (cve_id,),
    )
    attack_rows = await attack_cursor.fetchall()
    result["attack_mappings"] = [dict(r) for r in attack_rows]

    return result


async def get_latest_critical(
    days: int = 7,
    min_cvss: float = 9.0,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Get recently published critical CVEs."""
    conn = await get_connection()

    query = """
        SELECT c.*, k.date_added AS kev_date_added, k.due_date AS kev_due_date,
               k.required_action AS kev_required_action,
               k.known_ransomware_campaign_use AS kev_ransomware,
               e.epss_score, e.percentile AS epss_percentile
        FROM cves c
        LEFT JOIN cisa_kev k ON c.cve_id = k.cve_id
        LEFT JOIN epss_cache e ON c.cve_id = e.cve_id
        WHERE c.cvss_v3_score >= ?
          AND c.published_date >= datetime('now', ?)
        ORDER BY c.cvss_v3_score DESC, c.published_date DESC
        LIMIT ?
    """
    params = (min_cvss, f"-{days} days", limit)

    cursor = await conn.execute(query, params)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_top_kev_entries(
    limit: int = 10,
    sort_by: str = "date_added",
) -> list[dict[str, Any]]:
    """Get top KEV entries sorted by date_added or epss_score."""
    conn = await get_connection()

    if sort_by == "epss_score":
        order = "e.epss_score DESC NULLS LAST"
    else:
        order = "k.date_added DESC"

    query = f"""
        SELECT k.*, c.description, c.cvss_v3_score, c.cvss_v3_vector,
               c.severity, c.published_date, c.cwe_ids,
               e.epss_score, e.percentile AS epss_percentile
        FROM cisa_kev k
        LEFT JOIN cves c ON k.cve_id = c.cve_id
        LEFT JOIN epss_cache e ON k.cve_id = e.cve_id
        ORDER BY {order}
        LIMIT ?
    """

    cursor = await conn.execute(query, (limit,))
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_epss_scores(cve_ids: list[str]) -> list[dict[str, Any]]:
    """Get cached EPSS scores for given CVE IDs."""
    conn = await get_connection()

    placeholders = ",".join(["?"] * len(cve_ids))
    query = f"""
        SELECT e.*, c.severity, c.cvss_v3_score
        FROM epss_cache e
        LEFT JOIN cves c ON e.cve_id = c.cve_id
        WHERE e.cve_id IN ({placeholders})
    """

    cursor = await conn.execute(query, cve_ids)
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def upsert_cves(cves_data: list[dict[str, Any]]) -> int:
    """Bulk upsert CVE records. Returns count of upserted records."""
    conn = await get_connection()
    count = 0

    for cve in cves_data:
        await conn.execute(
            """INSERT INTO cves (
                cve_id, description, cvss_v3_score, cvss_v3_vector,
                cvss_v4_score, cvss_v4_vector, severity,
                published_date, last_modified_date,
                cwe_ids, references_json, cpe_match_json, raw_nvd_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_v3_score=excluded.cvss_v3_score,
                cvss_v3_vector=excluded.cvss_v3_vector,
                cvss_v4_score=excluded.cvss_v4_score,
                cvss_v4_vector=excluded.cvss_v4_vector,
                severity=excluded.severity,
                last_modified_date=excluded.last_modified_date,
                cwe_ids=excluded.cwe_ids,
                references_json=excluded.references_json,
                cpe_match_json=excluded.cpe_match_json,
                raw_nvd_json=excluded.raw_nvd_json
            """,
            (
                cve.get("cve_id"),
                cve.get("description", ""),
                cve.get("cvss_v3_score"),
                cve.get("cvss_v3_vector"),
                cve.get("cvss_v4_score"),
                cve.get("cvss_v4_vector"),
                cve.get("severity"),
                cve.get("published_date"),
                cve.get("last_modified_date"),
                cve.get("cwe_ids"),
                cve.get("references_json"),
                cve.get("cpe_match_json"),
                cve.get("raw_nvd_json"),
            ),
        )
        count += 1

    await conn.commit()
    return count


async def upsert_kev_entries(entries: list[dict[str, Any]]) -> int:
    """Bulk upsert CISA KEV entries. Returns count of upserted records."""
    conn = await get_connection()
    count = 0

    for entry in entries:
        cve_id = entry.get("cve_id")
        if not cve_id:
            continue

        # Ensure parent CVE stub exists to satisfy foreign key
        await conn.execute(
            """INSERT OR IGNORE INTO cves (
                cve_id, description, published_date, last_modified_date
            ) VALUES (?, ?, ?, ?)""",
            (
                cve_id,
                entry.get("short_description") or entry.get("vulnerability_name") or "CISA KEV listed vulnerability",
                entry.get("date_added") or "1970-01-01T00:00:00",
                entry.get("date_added") or "1970-01-01T00:00:00",
            ),
        )

        await conn.execute(
            """INSERT INTO cisa_kev (
                cve_id, vendor_project, product, vulnerability_name,
                date_added, short_description, required_action,
                due_date, known_ransomware_campaign_use, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor_project=excluded.vendor_project,
                product=excluded.product,
                vulnerability_name=excluded.vulnerability_name,
                date_added=excluded.date_added,
                short_description=excluded.short_description,
                required_action=excluded.required_action,
                due_date=excluded.due_date,
                known_ransomware_campaign_use=excluded.known_ransomware_campaign_use,
                notes=excluded.notes
            """,
            (
                cve_id,
                entry.get("vendor_project"),
                entry.get("product"),
                entry.get("vulnerability_name"),
                entry.get("date_added"),
                entry.get("short_description"),
                entry.get("required_action"),
                entry.get("due_date"),
                entry.get("known_ransomware_campaign_use"),
                entry.get("notes"),
            ),
        )
        count += 1

    await conn.commit()
    return count


async def upsert_epss_scores(scores: list[dict[str, Any]]) -> int:
    """Bulk upsert EPSS score records. Returns count of upserted records."""
    conn = await get_connection()
    count = 0

    for score in scores:
        await conn.execute(
            """INSERT INTO epss_cache (cve_id, epss_score, percentile, date_recorded)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss_score=excluded.epss_score,
                percentile=excluded.percentile,
                date_recorded=excluded.date_recorded,
                last_fetched_at=CURRENT_TIMESTAMP
            """,
            (
                score.get("cve_id"),
                score.get("epss_score"),
                score.get("percentile"),
                score.get("date_recorded"),
            ),
        )
        count += 1

    await conn.commit()
    return count


async def update_sync_state(
    source_name: str,
    timestamp: str,
    records_synced: int,
    status: str = "SUCCESS",
    error_message: str | None = None,
) -> None:
    """Update sync tracking state for a data source."""
    conn = await get_connection()
    await conn.execute(
        """INSERT INTO sync_state (source_name, last_sync_timestamp, records_synced, sync_status, error_message)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
            last_sync_timestamp=excluded.last_sync_timestamp,
            records_synced=excluded.records_synced,
            sync_status=excluded.sync_status,
            error_message=excluded.error_message
        """,
        (source_name, timestamp, records_synced, status, error_message),
    )
    await conn.commit()


async def get_sync_state(source_name: str) -> dict[str, Any] | None:
    """Get current sync state for a data source."""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT * FROM sync_state WHERE source_name = ?",
        (source_name,),
    )
    row = await cursor.fetchone()
    return dict(row) if row else None
