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
2. Dump: `sqlite-diffable dump <db> db_dump/ --all`.
3. **Commit the dump** (`git add db_dump/ && git commit`). Do not
   proceed to step 4 until the snapshot is in git history.
4. Dry-run on `/tmp/<name>.db`.
5. Apply to real db with explicit `-x db=`.
6. `alembic current` to confirm new revision.
7. Schema/EXPLAIN check.
8. Report what changed.
