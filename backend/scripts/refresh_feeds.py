"""
Scheduled / on-demand reputation feed refresh script.
Downloads recent feeds from OpenPhish and URLhaus and caches hashes in local SQLite database.
"""
from __future__ import annotations

import hashlib
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select, delete

project_root = Path(__file__).resolve().parent.parent.parent
backend_dir = project_root / "backend"
sys.path.insert(0, str(backend_dir))

from app.database.connection import get_db, init_db
from app.database.models import ReputationFeedEntry, FeedStatus
from app.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def refresh_openphish(db) -> int:
    logger.info("Refreshing OpenPhish feed...")
    count = 0
    now = datetime.now(timezone.utc)
    try:
        resp = httpx.get("https://openphish.com/feed.txt", follow_redirects=True, timeout=20.0)
        if resp.status_code == 200:
            urls = [line.strip() for line in resp.text.splitlines() if line.strip().startswith("http")]
            # Clear old entries for openphish
            db.execute(delete(ReputationFeedEntry).where(ReputationFeedEntry.source == "openphish"))

            for u in urls:
                h = hashlib.sha256(u.lower().encode()).hexdigest()
                db.add(ReputationFeedEntry(
                    source="openphish",
                    url_hash=h,
                    url=u,
                    fetched_at=now,
                    entry_meta={"source": "openphish_community"},
                ))
                count += 1

            status = db.execute(select(FeedStatus).where(FeedStatus.source == "openphish")).scalar_one_or_none()
            if not status:
                status = FeedStatus(source="openphish")
                db.add(status)
            status.last_success_at = now
            status.record_count = count
            status.last_error = None
            db.flush()
            logger.info(f"OpenPhish refreshed: {count} active entries cached.")
    except Exception as e:
        logger.error(f"Failed to refresh OpenPhish: {e}")
        status = db.execute(select(FeedStatus).where(FeedStatus.source == "openphish")).scalar_one_or_none()
        if not status:
            status = FeedStatus(source="openphish")
            db.add(status)
        status.last_error = str(e)
        db.flush()
    return count


def refresh_urlhaus(db, limit: int = 2000) -> int:
    logger.info("Refreshing URLhaus feed...")
    count = 0
    now = datetime.now(timezone.utc)
    try:
        resp = httpx.get("https://urlhaus.abuse.ch/downloads/csv_online/", follow_redirects=True, timeout=25.0)
        if resp.status_code == 200:
            db.execute(delete(ReputationFeedEntry).where(ReputationFeedEntry.source == "urlhaus"))
            lines = resp.text.splitlines()
            for line in lines:
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip('"\r\n ') for p in line.split(",")]
                if len(parts) >= 3:
                    u = parts[2]
                    if u.startswith("http"):
                        h = hashlib.sha256(u.lower().encode()).hexdigest()
                        db.add(ReputationFeedEntry(
                            source="urlhaus",
                            url_hash=h,
                            url=u,
                            fetched_at=now,
                            entry_meta={"threat": parts[3] if len(parts) > 3 else "malware"},
                        ))
                        count += 1
                        if count >= limit:
                            break

            status = db.execute(select(FeedStatus).where(FeedStatus.source == "urlhaus")).scalar_one_or_none()
            if not status:
                status = FeedStatus(source="urlhaus")
                db.add(status)
            status.last_success_at = now
            status.record_count = count
            status.last_error = None
            db.flush()
            logger.info(f"URLhaus refreshed: {count} active entries cached.")
    except Exception as e:
        logger.error(f"Failed to refresh URLhaus: {e}")
        status = db.execute(select(FeedStatus).where(FeedStatus.source == "urlhaus")).scalar_one_or_none()
        if not status:
            status = FeedStatus(source="urlhaus")
            db.add(status)
        status.last_error = str(e)
        db.flush()
    return count


def main():
    init_db()
    with get_db() as db:
        c1 = refresh_openphish(db)
        c2 = refresh_urlhaus(db)
        logger.info(f"Total reputation entries cached: {c1 + c2}")


if __name__ == "__main__":
    main()
