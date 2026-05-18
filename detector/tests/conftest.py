"""Test fixtures: build a real schema in a temp SQLite via alembic."""
import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    # alembic.ini holds the dev URL; override per-test.
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    cwd = os.getcwd()
    os.chdir(REPO_ROOT)
    try:
        command.upgrade(cfg, "head")
    finally:
        os.chdir(cwd)

    from lte_rogue_detector.db import connect
    return connect(str(db_path))


def insert_message(
    conn: sqlite3.Connection,
    *,
    ts: str,
    direction: str,
    nas_msg_type: str,
    enb_ue_s1ap_id: int | None,
    mme_ue_s1ap_id: int | None = None,
    plmn: str | None = None,
    cell_id: int | None = None,
    identity_type: str | None = None,
    eea_selected: int | None = None,
    eia_selected: int | None = None,
    ue_eea_caps: int | None = None,
    ue_eia_caps: int | None = None,
    emm_cause: int | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO messages (ts, direction, nas_msg_type, identity_type,"
        " eea_selected, eia_selected, ue_eea_caps, ue_eia_caps, emm_cause,"
        " enb_ue_s1ap_id, mme_ue_s1ap_id, plmn, cell_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ts, direction, nas_msg_type, identity_type,
            eea_selected, eia_selected, ue_eea_caps, ue_eia_caps, emm_cause,
            enb_ue_s1ap_id, mme_ue_s1ap_id, plmn, cell_id,
        ),
    )
    return cur.lastrowid
