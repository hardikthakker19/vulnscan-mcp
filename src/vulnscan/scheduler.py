"""APScheduler async background task manager for periodic sync."""

from __future__ import annotations

import asyncio
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from vulnscan.config import get_settings
from vulnscan.services.sync_service import (
    sync_cisa_kev,
    sync_epss_scores,
    sync_nvd_delta,
)

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def _run_async_job(coro_func):
    """Wrapper to run an async job function in the scheduler."""
    async def wrapper():
        try:
            await coro_func()
        except Exception as e:
            logger.error(f"Scheduled job {coro_func.__name__} failed: {e}", exc_info=True)
    return wrapper


async def start_scheduler() -> AsyncIOScheduler:
    """Initialize and start the APScheduler with all sync jobs."""
    global _scheduler

    if _scheduler is not None:
        return _scheduler

    settings = get_settings()
    scheduler = AsyncIOScheduler()

    # NVD Delta Sync (every N hours)
    scheduler.add_job(
        sync_nvd_delta,
        trigger=IntervalTrigger(hours=settings.nvd_sync_interval_hours),
        id="nvd_delta_sync",
        name="NVD Delta Sync",
        replace_existing=True,
        max_instances=1,
    )

    # CISA KEV Sync (every N hours)
    scheduler.add_job(
        sync_cisa_kev,
        trigger=IntervalTrigger(hours=settings.kev_sync_interval_hours),
        id="cisa_kev_sync",
        name="CISA KEV Sync",
        replace_existing=True,
        max_instances=1,
    )

    # EPSS Batch Enrichment (every N hours)
    scheduler.add_job(
        sync_epss_scores,
        trigger=IntervalTrigger(hours=settings.epss_sync_interval_hours),
        id="epss_batch_sync",
        name="EPSS Batch Enrichment",
        replace_existing=True,
        max_instances=1,
    )

    scheduler.start()
    _scheduler = scheduler

    logger.info(
        f"Scheduler started — NVD every {settings.nvd_sync_interval_hours}h, "
        f"KEV every {settings.kev_sync_interval_hours}h, "
        f"EPSS every {settings.epss_sync_interval_hours}h"
    )

    # Trigger initial sync after a short delay to not block startup
    asyncio.get_event_loop().call_later(
        5.0,
        lambda: asyncio.ensure_future(_initial_sync()),
    )

    return scheduler


async def _initial_sync() -> None:
    """Run initial sync for all sources on startup."""
    logger.info("Running initial background sync...")
    try:
        await sync_cisa_kev()
    except Exception as e:
        logger.error(f"Initial CISA KEV sync failed: {e}")

    try:
        await sync_epss_scores()
    except Exception as e:
        logger.error(f"Initial EPSS sync failed: {e}")

    # NVD delta sync last (slowest, rate-limited)
    try:
        await sync_nvd_delta()
    except Exception as e:
        logger.error(f"Initial NVD sync failed: {e}")

    logger.info("Initial background sync complete")


async def stop_scheduler() -> None:
    """Shutdown the scheduler gracefully."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler stopped")
