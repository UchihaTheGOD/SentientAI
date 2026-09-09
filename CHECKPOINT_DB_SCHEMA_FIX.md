# Checkpoint — Existing SQLite schema upgrade fix

**Date:** 2026-09-04
**Branch:** `redesign/public-site-and-security-foundation`
**Reported symptom:** `sqlite3.OperationalError: no such column: users.password_hash` on `GET /`.

---

## Root cause

Two things combined:

1. **`create_all` never alters an existing table.** SQLAlchemy's
   `Base.metadata.create_all` issues `CREATE TABLE IF NOT EXISTS` per table. A
   `users` table created under an older schema is skipped entirely, so any column
   added to the `User` model *after* that table first existed
   (`password_hash`, and the other redesign columns) is never created.
2. **The old migration hand-list omitted `password_hash`.** The previous
   `_run_migrations()` was a hand-maintained list of `ALTER TABLE … ADD COLUMN`
   statements. It happened to add `display_name`, `bio`, `token_version`,
   `is_suspended`, etc., but **not** `password_hash` — so even the upgrade path
   left the reported column missing.

## Migration strategy (the fix)

`app/database.py` now upgrades existing databases with a **model-driven**
migration instead of a hand-maintained list:

- For every table mapped on `Base` that already exists, it diffs the model's
  declared columns against the live table (via the SQLAlchemy inspector) and
  `ALTER TABLE … ADD COLUMN`s any that are missing. **The source of truth is the
  models**, so it can never again "forget" a column such as `password_hash`.
- **SQLite constraint handling:** new columns are added *nullable* (SQLite cannot
  add a `NOT NULL` column without a default). Scalar model defaults are backfilled
  (`token_version` → 0, `status` → `'candidate'`, …). A pre-existing row for which
  no real value can be invented — a legacy account has no password hash — gets
  `NULL` and simply cannot sign in until its password is reset (the safe outcome).
  New inserts still flow through the ORM, which enforces the model's `NOT NULL`.
- The existing **value backfills** (blog post `status`/`published_at`/`is_hidden`,
  user `is_suspended`/`token_version`, comment `is_hidden`, training-example
  lifecycle) are preserved.
- **Non-destructive:** `init_db()` never drops or deletes. Tables present in the
  database that no model maps (legacy leftovers) are left untouched.
- `init_db(bind=…)` / `_run_migrations(bind=…)` gained an optional engine
  argument so the regression test can target a throwaway database; every existing
  no-arg caller (`manage.py`, `app/cli.py`, `app/main.py`, `conftest.py`) is
  unchanged.
- **`reset-db --yes` behaviour is unchanged:** `drop_all` → `create_all` →
  migrate → seed exactly one admin. Still the only destructive path, still
  requires `--yes`. `init_db`/startup never deletes automatically.

## Files changed

| File | Change |
| --- | --- |
| `app/database.py` | Rewrote the schema-upgrade layer as a model-driven migration; updated module docstring; removed the now-dead `_safe_add_column`; `init_db`/`_run_migrations` accept an optional `bind`. |
| `tests/test_schema_migration.py` | **New.** Regression tests for the upgrade path. |
| `DOCUMENTATION.md` | §6 and §19 updated to describe the real mechanism and the correct init/upgrade/reset procedure. |

No UI, route, feature, or model file was modified (requirement: do not modify
unrelated features).

## Tests run / results

- **New regression file:** `pytest tests/test_schema_migration.py` → **4 passed**,
  including `test_old_users_table_without_password_hash_is_upgraded` (builds a
  real legacy `users` table with no `password_hash` + a legacy row, runs
  `init_db`, asserts the column and all redesign columns are added, the legacy
  row is preserved with `password_hash IS NULL`, and `SELECT … User` works).
- **Full suite:** `pytest -p no:warnings -rs` → **417 passed, 1 skipped, 0 failed**
  (was 413; the 4 new tests are the difference). The single skip is the
  pre-existing intentional `partials/nav.html` template skip.
- **`reset-db --yes` against a temp DB:** rebuilt all 19 tables, `users` has
  `password_hash` (15 columns), and seeded one admin with an Argon2id hash.

## How the existing database was handled

**Honest note on the real file's current state.** The on-disk
`data/sentientai.db` **already had `password_hash`** (all 15 current `users`
columns) and was **empty (0 users)** when this fix began — most likely because a
prior-session boot already ran the new `init_db` against it and healed the
column. So the reported error does **not** reproduce against the real file *in
its present state*.

- **The bug was reproduced against a genuine old-schema database** (a `users`
  table without `password_hash` plus a legacy row): before the fix a `User`
  query raised the exact `OperationalError`; after `init_db` the column and every
  redesign column are present, the legacy row is preserved (`password_hash =
  NULL`), and `GET /` returns 200. This is captured permanently by the regression
  test so it cannot silently regress.
- The real `data/sentientai.db` also contains **6 orphan tables** from the
  project's earlier "security-testing" era (`analysis_feedback`,
  `dataset_versions`, `evaluation_runs`, `lab_sessions`, `model_checkpoints`,
  `security_events`) that no current model maps. The non-destructive upgrade
  correctly leaves them untouched; the app works with them present. Running
  `reset-db --yes` would drop them for a schema that matches the models exactly —
  optional, not required.

**Verification against the real file (both scenarios — requirement #10):**

- **Fresh empty database:** boots, `GET /` = 200, full 15-column `users` schema.
- **Old database (no `password_hash`):** boots, upgrades in place, `GET /` = 200,
  legacy row preserved.
- **Stage 1 — the real `data/sentientai.db`:** booted the *real* app against it
  (a timestamped backup was taken first); `GET /` = 200 with 0 users; seeded the
  bootstrap admin; `GET /` = 200 with the admin present (homepage user query
  works); exactly one admin with an Argon2id hash. The real DB was left as a
  **clean bootstrap** (current schema + one admin, 0 audit rows).
- **Stage 2 — a copy of the upgraded real DB:** admin login
  (`admin` / `admin@12345`) → 303 + session cookie → `/dashboard` 200;
  registration → 303 → `/login?registered=1` (row created); new-user login → 303
  + cookie → `/dashboard` 200; homepage with multiple users → 200. These
  write-flows ran on the copy so the real file stayed pristine.

## Current state

- **`data/sentientai.db`**: current schema, `password_hash` present, exactly one
  admin (`admin` / `admin@12345`), boots and serves `GET /` = 200. **Change the
  admin password after first sign-in.**
- `GET /` returns **200** against the actual local database — the task's
  completion bar is met.

## Next steps (only if desired)

- None required for the fix.
- Optional: `python manage.py reset-db --yes` to drop the 6 orphan legacy tables
  for a schema that exactly matches the current models (destructive — recreates
  schema + one admin).
- Change the bootstrap admin password on first sign-in in any real deployment.
