---
name: migrate
description: Run an Alembic migration safely. Use BEFORE any `alembic upgrade`, `alembic downgrade`, or any other invocation that mutates a real SQLite db's schema. Trigger on user phrases like "run the migration", "apply the migration", "upgrade the db", "downgrade", "alembic upgrade/downgrade", or any time the model is about to invoke alembic against a non-throwaway db.
---

# migrate

## Rules

### 1. NEVER migrate without a snapshot first
Before invoking `alembic upgrade` or `alembic downgrade` against any db
that is not under `/tmp/` or an obvious throwaway path, dump the db to
a diffable directory:

```
sqlite-diffable dump <db_path> <db_path>.dump.<UTC-timestamp>/ --all
```

No exceptions. Even for "harmless" migrations like `CREATE INDEX`. The
cost of the dump is seconds; the cost of a botched downgrade is hours.

Restore later with:

```
sqlite-diffable load <db_path>.restored <db_path>.dump.<ts>/
```

### 2. Always pass `-x db=<path>` explicitly
Never rely on `alembic.ini`'s default `sqlalchemy.url`. Always specify
the target db on the command line so it's obvious which db is being
touched. Example:

```
alembic -x db=detector.db upgrade head
```

If the user hasn't told you which db to target, ask.

### 3. Verify migration syntax on a fresh throwaway db first
Before touching the real db, run the full chain on `/tmp/<name>.db`:

```
rm -f /tmp/migtest.db
alembic -x db=/tmp/migtest.db upgrade head
```

Confirm it completes cleanly. Only then proceed to the real db.

### 4. After applying, confirm the revision and the schema change
```
alembic -x db=<path> current
sqlite3 <path> "<EXPLAIN or schema-check query>"
```

If the change is an index, run `EXPLAIN QUERY PLAN` against a
representative query to confirm SQLite actually uses it.

### 5. If a downgrade fails mid-batch
Stop. Do not retry with `--sql` or `-x` tricks. Investigate the error
(usually NOT NULL or FK violation from data the prior schema doesn't
accept). Either fix the data, write a data-migration step, or accept
that the downgrade isn't reversible against this db and restore from
the dump taken in rule 1.

### 6. Order of operations (the checklist)
1. Confirm target db path with the user.
2. Dump: `sqlite-diffable dump <db> <db>.dump.<ts>/ --all`.
3. Dry-run on `/tmp/<name>.db`.
4. Apply to real db with explicit `-x db=`.
5. `alembic current` to confirm new revision.
6. Schema/EXPLAIN check.
7. Report what changed.
