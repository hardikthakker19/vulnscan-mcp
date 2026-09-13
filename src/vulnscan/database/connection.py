"""Async SQLite connection manager with WAL mode."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from vulnscan.config import get_settings

logger = logging.getLogger(__name__)

_db_connection: aiosqlite.Connection | None = None


async def get_db_path() -> Path:
    """Get the database file path, ensuring the directory exists."""
    settings = get_settings()
    db_path = settings.db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


async def init_connection() -> aiosqlite.Connection:
    """Initialize and return a persistent database connection with WAL mode."""
    global _db_connection
    if _db_connection is not None:
        return _db_connection

    db_path = await get_db_path()
    logger.info(f"Connecting to database: {db_path}")

    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row

    # Use DELETE journal mode by default for robust compatibility across host bind mounts (e.g. Docker on Windows)
    import os
    journal_mode = os.getenv("SQLITE_JOURNAL_MODE", "DELETE").upper()
    await conn.execute(f"PRAGMA journal_mode={journal_mode}")
    logger.info(f"Database connection established with {journal_mode} mode")
    await conn.execute("PRAGMA busy_timeout=5000")
    await conn.execute("PRAGMA synchronous=NORMAL")
    await conn.execute("PRAGMA cache_size=-64000")  # 64MB cache
    await conn.execute("PRAGMA foreign_keys=ON")

    _db_connection = conn
    return conn


async def get_connection() -> aiosqlite.Connection:
    """Get the current database connection, initializing if needed."""
    global _db_connection
    if _db_connection is None:
        return await init_connection()
    return _db_connection


@asynccontextmanager
async def get_cursor() -> AsyncGenerator[aiosqlite.Cursor, None]:
    """Context manager that provides a database cursor."""
    conn = await get_connection()
    cursor = await conn.cursor()
    try:
        yield cursor
        await conn.commit()
    except Exception:
        await conn.rollback()
        raise
    finally:
        await cursor.close()


async def close_connection() -> None:
    """Close the database connection."""
    global _db_connection
    if _db_connection is not None:
        await _db_connection.close()
        _db_connection = None
        logger.info("Database connection closed")
