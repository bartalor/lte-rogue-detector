"""SQLite connection helper.

Centralises the two settings that matter for correctness: foreign-key
enforcement (off by default in SQLite) and `row_factory` so rules read
columns by name.
"""
import sqlite3
from contextlib import contextmanager
from typing import Iterator


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
