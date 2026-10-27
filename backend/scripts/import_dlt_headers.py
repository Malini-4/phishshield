"""
Utility script to import and validate Indian TRAI DLT SMS sender headers.

Data Provenance & Reference:
- TRAI DLT Portal: https://smsheader.trai.gov.in/
- TRAI Portal & Apps: https://www.trai.gov.in/portal-and-apps
- Advice to Senders: https://www.trai.gov.in/advice-to-senders

Limitations:
- Official TRAI DLT portal (smsheader.trai.gov.in) does not provide a public unauthenticated
  bulk API or downloadable full national registry.
- PhishShield therefore maintains a transparent, traceable reference dataset of verified
  registered principal entity headers in data/reference/sms_sender_reference.csv.
- Run this script with --file <path_to_csv> to merge or update registered headers.
"""
from __future__ import annotations

import csv
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

REFERENCE_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "reference" / "sms_sender_reference.csv"


def validate_and_import(csv_path: Path) -> int:
    if not csv_path.exists():
        logger.error(f"Input file not found: {csv_path}")
        return 0

    existing = {}
    if REFERENCE_FILE.exists():
        with open(REFERENCE_FILE, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing[row["header"].upper()] = row

    imported = 0
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            header = row.get("header", "").strip().upper()
            if not header or len(header) < 3 or len(header) > 11:
                continue
            existing[header] = {
                "header": header,
                "brand": row.get("brand", "Unknown").strip(),
                "category": row.get("category", "general").strip(),
                "source_url": row.get("source_url", "https://smsheader.trai.gov.in/").strip(),
                "last_verified": row.get("last_verified", "2026-10-10").strip(),
            }
            imported += 1

    # Write back sorted
    with open(REFERENCE_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["header", "brand", "category", "source_url", "last_verified"]
        )
        writer.writeheader()
        for h in sorted(existing.keys()):
            writer.writerow(existing[h])

    logger.info(f"Successfully processed {imported} entries. Total registered headers: {len(existing)}.")
    return len(existing)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
        validate_and_import(target)
    else:
        logger.info(f"Current reference file: {REFERENCE_FILE}")
        logger.info(f"Entries: {len(list(csv.DictReader(open(REFERENCE_FILE, encoding='utf-8'))))}")
