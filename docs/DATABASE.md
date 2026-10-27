# PhishShield Database Architecture & Migration Procedure

---

## 1. Schema Design

PhishShield uses SQLite with SQLAlchemy 2.x and Alembic.

### Key Tables
1. **`investigations`**:
   - `id`: UUID (Primary Key)
   - `type`: `url`, `apk`, `sms`, `screenshot`
   - `created_at`: DateTime UTC with timezone
   - `verdict`: `malicious`, `suspicious`, `clean_no_findings`, `inconclusive`
   - `display_label`: String
   - `summary`: Text
   - `input_display`: Redacted safe text representation
   - `input_hash`: SHA-256 of raw input
   - `status`: `completed`, `failed`
   - `duration_ms`: Latency in milliseconds
   - `result_json`: Full structured JSON result matching Pydantic schema

2. **`evidence_items`**:
   - Foreign Key to `investigations.id` (ON DELETE CASCADE)
   - `category`, `severity` (`high`, `medium`, `low`, `info`), `title`, `detail`, `source`

3. **`checks`**:
   - Foreign Key to `investigations.id` (ON DELETE CASCADE)
   - `name`, `status` (`completed`, `failed`, `unavailable`, `skipped`), `detail`

4. **Module Detail Tables** (`url_details`, `apk_details`, `sms_details`, `screenshot_details`):
   - One-to-one child tables with CASCADE deletion for detailed module-specific storage.

5. **`reputation_feed_entries`** & **`feed_status`**:
   - Caches SHA-256 hashes of open threat feeds (URLhaus, OpenPhish) to enable local reputation lookups.

---

## 2. SQLite Performance Pragmas

On every connection, PhishShield executes:
```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;
```
- **WAL Mode:** Allows simultaneous readers and single-writer concurrency without table locks.
- **Foreign Keys:** Enforces referential integrity on deletes.

---

## 3. Migration Procedure

Migrations are managed with Alembic.

1. **Apply Current Migrations:**
   ```bash
   cd backend
   .\.venv\Scripts\alembic upgrade head
   ```

2. **Creating a New Migration (Preserving Data):**
   ```bash
   cd backend
   .\.venv\Scripts\alembic revision --autogenerate -m "add_column_name"
   ```
   Inspect the generated script in `alembic/versions/` to verify SQLite batch operations (`render_as_batch=True`).

3. **Rolling Back:**
   ```bash
   cd backend
   .\.venv\Scripts\alembic downgrade -1
   ```
