"""Database schema creation, FTS5 triggers, and data migration."""

from __future__ import annotations

import logging

import aiosqlite

from vulnscan.database.connection import get_connection

logger = logging.getLogger(__name__)

# ─── Schema DDL ─────────────────────────────────────────────────────────────

SCHEMA_SQL = """
-- Core CVE Registry
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cvss_v4_score REAL,
    cvss_v4_vector TEXT,
    severity TEXT,
    published_date TEXT NOT NULL,
    last_modified_date TEXT NOT NULL,
    cwe_ids TEXT,
    references_json TEXT,
    cpe_match_json TEXT,
    raw_nvd_json TEXT
);

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
    tactic_id TEXT NOT NULL,
    tactic_name TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
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
"""

FTS5_SQL = """
-- Full Text Search Index
CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    cve_id,
    description,
    cpe_match_json,
    content='cves',
    content_rowid='rowid'
);
"""

FTS5_TRIGGERS_SQL = """
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
"""

# ─── Migration from legacy 'vulnerabilities' table ──────────────────────────

MIGRATION_SQL = """
INSERT OR IGNORE INTO cves (
    cve_id, description, cvss_v3_score, cvss_v3_vector,
    severity, published_date, last_modified_date,
    references_json, cpe_match_json
)
SELECT
    cve_id,
    COALESCE(description, ''),
    cvss_score,
    cvss_vector,
    severity,
    COALESCE(published_date, datetime('now')),
    COALESCE(last_modified_date, datetime('now')),
    references_json,
    affected_products
FROM vulnerabilities
WHERE cve_id IS NOT NULL;
"""

MIGRATE_KEV_SQL = """
INSERT OR IGNORE INTO cisa_kev (cve_id, date_added, due_date)
SELECT cve_id, created_at, kev_due_date
FROM vulnerabilities
WHERE is_in_kev = 1 AND cve_id IS NOT NULL;
"""


# Legacy tables from older database versions to drop
LEGACY_TABLES_TO_DROP = [
    "alerts",
    "components",
    "scan_results",
    "scan_runs",
    "schema_migrations",
    "vulnerabilities",
]


async def _table_exists(conn: aiosqlite.Connection, table_name: str) -> bool:
    """Check if a table exists in the database."""
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    row = await cursor.fetchone()
    return row is not None


async def _rebuild_fts_index(conn: aiosqlite.Connection) -> None:
    """Populate FTS5 index from existing cves data."""
    logger.info("Rebuilding FTS5 index from cves table...")
    await conn.execute("INSERT INTO cves_fts(cves_fts) VALUES('rebuild')")
    await conn.commit()
    logger.info("FTS5 index rebuilt successfully")


async def initialize_schema() -> None:
    """Create all tables, FTS5 index, triggers, and migrate legacy data."""
    conn = await get_connection()

    # Check if this is first run with the new schema
    cves_existed = await _table_exists(conn, "cves")
    has_legacy = await _table_exists(conn, "vulnerabilities")

    # Create core tables and indexes
    logger.info("Creating database schema...")
    for statement in SCHEMA_SQL.split(";"):
        statement = statement.strip()
        if statement:
            await conn.execute(statement)
    await conn.commit()

    # Create FTS5 virtual table
    logger.info("Creating FTS5 virtual table...")
    await conn.execute(FTS5_SQL.strip())
    await conn.commit()

    # Create FTS5 triggers (each trigger is a separate statement)
    logger.info("Creating FTS5 triggers...")
    for statement in FTS5_TRIGGERS_SQL.split("END;"):
        statement = statement.strip()
        if statement:
            await conn.execute(statement + "END;")
    await conn.commit()

    # Migrate legacy data if needed
    if has_legacy and not cves_existed:
        logger.info("Migrating data from legacy 'vulnerabilities' table...")
        cursor = await conn.execute("SELECT COUNT(*) FROM vulnerabilities")
        row = await cursor.fetchone()
        legacy_count = row[0] if row else 0
        logger.info(f"Found {legacy_count} records in legacy table")

        await conn.execute(MIGRATION_SQL)
        await conn.execute(MIGRATE_KEV_SQL)
        await conn.commit()

        cursor = await conn.execute("SELECT COUNT(*) FROM cves")
        row = await cursor.fetchone()
        migrated_count = row[0] if row else 0
        logger.info(f"Migrated {migrated_count} CVE records to new schema")

        # Rebuild FTS index after migration
        await _rebuild_fts_index(conn)
    elif not cves_existed:
        logger.info("Fresh database — no legacy data to migrate")

    # Drop obsolete legacy tables if they exist
    dropped_legacy = []
    for table_name in LEGACY_TABLES_TO_DROP:
        if await _table_exists(conn, table_name):
            logger.info(f"Dropping obsolete legacy table: {table_name}")
            await conn.execute(f"DROP TABLE IF EXISTS {table_name}")
            dropped_legacy.append(table_name)
    if dropped_legacy:
        await conn.commit()
        logger.info(f"Cleaned up legacy tables: {', '.join(dropped_legacy)}")

    # Initialize sync_state entries
    await conn.execute("""
        INSERT OR IGNORE INTO sync_state (source_name, last_sync_timestamp, records_synced)
        VALUES ('NVD', '1970-01-01T00:00:00Z', 0),
               ('CISA_KEV', '1970-01-01T00:00:00Z', 0),
               ('EPSS', '1970-01-01T00:00:00Z', 0)
    """)
    await conn.commit()

    logger.info("Database schema initialization complete")
