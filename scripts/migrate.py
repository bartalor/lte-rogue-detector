#!/usr/bin/env python3
"""Apply an Alembic migration to a real SQLite db with the safety
checklist from .claude/skills/migrate enforced in code.

Usage:
    scripts/migrate.py <db_path> [alembic-target]

    <db_path>          path to the SQLite db to migrate (e.g. detector.db)
    [alembic-target]   alembic revision (default: head)

What it does:
    1. Refuses to run with uncommitted changes (so the snapshot commit
       is isolated from unrelated work).
    2. Dumps <db_path> to db_dump/ via sqlite-diffable.
    3. Commits db_dump/ to git (the snapshot lives in history before
       the risky operation, not after).
    4. Dry-runs the migration on a throwaway db (./.migtest.db,
       gitignored, removed before AND after — never /tmp, which can be
       tmpfs-backed).
    5. Verifies the dry-run override actually took effect.
    6. Applies the migration to <db_path>.
    7. Confirms the new revision.

This project's alembic/env.py reads LTE_ROGUE_DB, not alembic's -x db=
flag, so the script uses the env var.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_TOOLS = ("git", "alembic", "sqlite3", "sqlite-diffable")


def run(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> str:
    full_env = {**os.environ, **(env or {})}
    result = subprocess.run(cmd, env=full_env, capture_output=True, text=True)
    if check and result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return result.stdout


def alembic_current(db: str) -> str:
    """Return the alembic revision for `db`, or '' for an unmigrated db.

    Crashes hard if alembic itself fails — an unmigrated db is fine
    (no revision row, no output match), but alembic erroring is not.
    """
    out = run(["alembic", "current"], env={"LTE_ROGUE_DB": db}, check=True)
    m = re.search(r"^([a-f0-9]{8,})", out, re.MULTILINE)
    return m.group(1) if m else ""


def main() -> int:
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        sys.stderr.write("usage: scripts/migrate.py <db_path> [alembic-target]\n")
        return 2

    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        sys.stderr.write(f"error: required tools missing from PATH: {', '.join(missing)}\n")
        return 2

    db = str(Path(sys.argv[1]).resolve())
    target = sys.argv[2] if len(sys.argv) == 3 else "head"

    if not Path(db).is_file():
        sys.stderr.write(f"error: {db} does not exist\n")
        return 2

    repo_root = run(["git", "rev-parse", "--show-toplevel"]).strip()
    os.chdir(repo_root)

    dirty = run(["git", "status", "--porcelain"]).strip()
    if dirty:
        sys.stderr.write(
            "error: working tree dirty. commit or stash first so the\n"
            "       snapshot commit only contains db_dump/.\n"
        )
        sys.stderr.write(dirty + "\n")
        return 1

    print(f"==> 1/6 snapshot {db} to db_dump/")
    if Path("db_dump").exists():
        shutil.rmtree("db_dump")
    run(["sqlite-diffable", "dump", db, "db_dump/", "--all"])

    print("==> 2/6 commit snapshot")
    run(["git", "add", "db_dump/"])
    run(["git", "commit", "-m", f"Snapshot {db} before {target}"])
    snapshot_commit = run(["git", "rev-parse", "--short", "HEAD"]).strip()

    print("==> 3/6 dry-run on ./.migtest.db")
    Path(".migtest.db").unlink(missing_ok=True)
    # Seed the throwaway with the same schema as the real db, so the
    # dry-run exercises the actual upgrade step (not just create-from-empty).
    dump = subprocess.run(
        ["sqlite3", db, ".dump"], capture_output=True, text=True, check=True
    ).stdout
    subprocess.run(
        ["sqlite3", ".migtest.db"], input=dump, text=True, check=True
    )

    real_revision = alembic_current(db)
    pre_revision = alembic_current(".migtest.db")
    if not real_revision:
        sys.stderr.write(
            f"error: {db} reports no alembic revision. The script only\n"
            "       handles forward migrations from an already-initialized\n"
            "       db. Initialize it first or use alembic directly.\n"
        )
        Path(".migtest.db").unlink(missing_ok=True)
        return 1
    if pre_revision != real_revision:
        sys.stderr.write(
            "error: LTE_ROGUE_DB override does not seem to be working.\n"
            f"       .migtest.db reports revision '{pre_revision}'\n"
            f"       {db} reports revision '{real_revision}'\n"
            "       they should match (both seeded from the real db).\n"
        )
        Path(".migtest.db").unlink(missing_ok=True)
        return 1

    run(["alembic", "upgrade", target], env={"LTE_ROGUE_DB": ".migtest.db"})
    dry_run_head = alembic_current(".migtest.db")
    print(f"    dry-run reached revision: {dry_run_head}")
    Path(".migtest.db").unlink(missing_ok=True)

    print(f"==> 4/6 apply to {db}")
    run(["alembic", "upgrade", target], env={"LTE_ROGUE_DB": db})

    print(f"==> 5/6 confirm new revision on {db}")
    new_revision = alembic_current(db)
    print(f"    {db} is now at revision: {new_revision}")

    if new_revision != dry_run_head:
        sys.stderr.write(
            f"error: real-db revision ({new_revision}) does not match\n"
            f"       dry-run revision ({dry_run_head}). The dry-run and the\n"
            "       real upgrade diverged — investigate before trusting the db.\n"
        )
        return 1

    print("==> 6/6 done.")
    print(f"    snapshot:        commit {snapshot_commit} (db_dump/)")
    print(f"    revision before: {real_revision}")
    print(f"    revision after:  {new_revision}")
    print()
    print("    to restore the pre-migration db:")
    print(f"      sqlite-diffable load {db}.restored db_dump/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
