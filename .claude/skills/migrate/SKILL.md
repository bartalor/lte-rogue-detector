---
name: migrate
description: Run an Alembic migration safely. Use BEFORE any `alembic upgrade`, `alembic downgrade`, or any other invocation that mutates a real SQLite db's schema. Trigger on user phrases like "run the migration", "apply the migration", "upgrade the db", "downgrade", "alembic upgrade/downgrade", or any time the model is about to invoke alembic against a non-throwaway db.
---

# migrate

Run `scripts/migrate.py <db_path> [target]`. That's it.

The script snapshots the db, commits the snapshot, applies the
migration, and reports the before/after revision. Do not run `alembic
upgrade` or `alembic downgrade` by hand against a non-throwaway db.
