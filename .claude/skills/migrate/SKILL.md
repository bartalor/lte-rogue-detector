---
name: migrate
description: Run an Alembic migration safely. Use BEFORE any `alembic upgrade`, `alembic downgrade`, or any other invocation that mutates a real SQLite db's schema. Trigger on user phrases like "run the migration", "apply the migration", "upgrade the db", "downgrade", "alembic upgrade/downgrade", or any time the model is about to invoke alembic against a non-throwaway db.
---

# migrate

## Rules

### 1. NEVER migrate without a committed snapshot first
Before invoking `alembic upgrade` or `alembic downgrade` against any db
that is not under `/tmp/` or an obvious throwaway path:

1. Dump the db to `db_dump/`:

   ```
   sqlite-diffable dump <db_path> db_dump/ --all
   ```

   Always use the directory name `db_dump/`. Do not invent timestamped
   or per-migration names; the snapshot is meant to be overwritten each
   time, and git history is what preserves prior snapshots.

2. **Commit the dump to git in its own commit, before running alembic.**
   A snapshot sitting untracked in the working tree is not a snapshot —
   one `git clean -fd` or accidental `rm -rf` and it is gone. The whole
   point of the dump is that it survives mistakes, so it has to live in
   git history before the risky operation, not after.

   ```
   git add db_dump/
   git commit -m "Snapshot <db_path> before <revision>"
   ```

No exceptions on either step. Even for "harmless" migrations like
`CREATE INDEX`. The cost of the dump+commit is seconds; the cost of a
botched downgrade with no recoverable snapshot is hours.

Restore later with:

```
sqlite-diffable load <db_path>.restored db_dump/
```

To recover an older snapshot, `git checkout <commit> -- db_dump/` first,
then run the load.

### 2. Always pass `LTE_ROGUE_DB=<path>` explicitly
This project's `alembic/env.py` reads the target db from the
`LTE_ROGUE_DB` environment variable, **not** from alembic's `-x` flag.
The `-x db=` flag is silently ignored — alembic falls back to
`alembic.ini`'s default (`detector.db`). Never rely on the default.
Always set the env var so it is obvious which db is being touched:

```
LTE_ROGUE_DB=detector.db alembic upgrade head
```

If the user hasn't told you which db to target, ask.

### 3. Verify migration syntax on a fresh throwaway db first
Before touching the real db, run the full chain on `/tmp/<name>.db`,
and **confirm the override took effect** before trusting the result:

```
rm -f /tmp/migtest.db
LTE_ROGUE_DB=/tmp/migtest.db alembic current   # must be empty (no revision)
LTE_ROGUE_DB=/tmp/migtest.db alembic upgrade head
LTE_ROGUE_DB=/tmp/migtest.db alembic current   # must report new head
ls -la /tmp/migtest.db                          # file must be non-zero size
```

If `alembic current` before the upgrade reports anything other than
empty, the override was ignored and alembic is hitting the real db.
Stop and investigate.

### 4. After applying, confirm the revision and the schema change
```
LTE_ROGUE_DB=<path> alembic current
sqlite3 <path> "<EXPLAIN or schema-check query>"
```

If the change is an index, run `EXPLAIN QUERY PLAN` against a
representative query to confirm SQLite actually uses it. (Note: a
partial index only gets picked when matching rows exist; if the
predicate matches zero rows the planner correctly skips it.)

### 5. If a downgrade fails mid-batch
Stop. Do not retry with `--sql` or `-x` tricks. Investigate the error
(usually NOT NULL or FK violation from data the prior schema doesn't
accept). Either fix the data, write a data-migration step, or accept
that the downgrade isn't reversible against this db and restore from
the dump taken in rule 1.

### 6. Order of operations (the checklist)
1. Confirm target db path with the user.
2. Dump: `sqlite-diffable dump <db> db_dump/ --all`.
3. **Commit the dump** (`git add db_dump/ && git commit`). Do not
   proceed to step 4 until the snapshot is in git history.
4. Dry-run on `/tmp/<name>.db` with `LTE_ROGUE_DB=/tmp/<name>.db`,
   verifying the override took effect (see rule 3).
5. Apply to real db with `LTE_ROGUE_DB=<path>`.
6. `LTE_ROGUE_DB=<path> alembic current` to confirm new revision.
7. Schema/EXPLAIN check.
8. Report what changed.
