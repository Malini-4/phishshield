# PhishShield Data Directory

- `data/raw/`: Cache directory for downloaded open threat feeds (URLhaus, OpenPhish, Tranco list). Excluded from git.
- `data/processed/`: Processed training, validation, test, and sanity datasets split grouped by domain. Excluded from git.
- `data/reference/`: Curated reference data checked into source control:
  - `brand_domains.csv`: Curated brand official domains.
  - `tunnel_hosts.csv`: Curated reverse-proxy / tunnel domains.
  - `sms_sender_reference.csv`: Curated verified Indian TRAI DLT alphanumeric header registrations.
  - `apk_rules.yaml`: Static APK rule configuration.
- `data/phishshield.db`: SQLite production database file (WAL mode enabled). Excluded from git.
