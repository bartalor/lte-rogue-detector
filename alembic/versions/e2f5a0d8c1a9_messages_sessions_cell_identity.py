"""messages, sessions: add plmn + cell_id

Revision ID: e2f5a0d8c1a9
Revises: d1a7f3e2c9b4
Create Date: 2026-05-18 09:00:00.000000

The sessionizer keyed sessions by enb_ue_s1ap_id alone. That ID is unique
only within an eNB (TS 36.413), so two cells observed in the same pcap
with the same enb_ue_s1ap_id collapsed into one session — masking rogue
behaviour on one cell with legitimate behaviour on another. The sniffer
now parses EUTRAN-CGI from S1AP InitialUEMessage / UplinkNASTransport;
this migration adds the columns to hold it. Downlink rows have no cell
IE on the wire, so both columns are nullable.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e2f5a0d8c1a9"
down_revision: Union[str, Sequence[str], None] = "d1a7f3e2c9b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("messages") as batch:
        batch.add_column(sa.Column("plmn", sa.Text))
        batch.add_column(sa.Column("cell_id", sa.Integer))
    # sessions.cell_id was an FK -> cells(cell_id) from the initial schema
    # but `cells` is never populated (no rule needs it yet). The sessionizer
    # now records EUTRAN-CGI directly on the session row, so we repurpose
    # cell_id for the 28-bit Cell Identity and drop the dead FK. SQLite
    # can't drop a constraint in place — rebuild the table manually.
    op.execute("PRAGMA foreign_keys = OFF")
    op.execute("""
        CREATE TABLE sessions_new (
            session_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            cell_id INTEGER,
            enb_ue_s1ap_id INTEGER NOT NULL,
            mme_ue_s1ap_id INTEGER,
            imsi TEXT,
            guti TEXT,
            tmsi TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            plmn TEXT,
            CONSTRAINT uq_sessions_cell_enbueid_started
                UNIQUE (cell_id, enb_ue_s1ap_id, started_at)
        )
    """)
    op.execute("""
        INSERT INTO sessions_new
            (session_id, cell_id, enb_ue_s1ap_id, mme_ue_s1ap_id,
             imsi, guti, tmsi, started_at, ended_at)
        SELECT session_id, cell_id, enb_ue_s1ap_id, mme_ue_s1ap_id,
               imsi, guti, tmsi, started_at, ended_at
        FROM sessions
    """)
    op.execute("DROP TABLE sessions")
    op.execute("ALTER TABLE sessions_new RENAME TO sessions")
    op.execute("CREATE INDEX idx_sessions_cell ON sessions (cell_id)")
    op.execute("CREATE INDEX idx_sessions_started_at ON sessions (started_at)")
    op.execute("PRAGMA foreign_keys = ON")

    op.create_index(
        "idx_messages_cell_enb_ue_s1ap_id",
        "messages",
        ["plmn", "cell_id", "enb_ue_s1ap_id", "ts"],
    )


def downgrade() -> None:
    op.drop_index("idx_messages_cell_enb_ue_s1ap_id", table_name="messages")
    op.execute("PRAGMA foreign_keys = OFF")
    op.execute("""
        CREATE TABLE sessions_new (
            session_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            cell_id INTEGER REFERENCES cells(cell_id),
            enb_ue_s1ap_id INTEGER NOT NULL,
            mme_ue_s1ap_id INTEGER,
            imsi TEXT,
            guti TEXT,
            tmsi TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            CONSTRAINT uq_sessions_cell_enbueid_started
                UNIQUE (cell_id, enb_ue_s1ap_id, started_at)
        )
    """)
    op.execute("""
        INSERT INTO sessions_new
            (session_id, cell_id, enb_ue_s1ap_id, mme_ue_s1ap_id,
             imsi, guti, tmsi, started_at, ended_at)
        SELECT session_id, cell_id, enb_ue_s1ap_id, mme_ue_s1ap_id,
               imsi, guti, tmsi, started_at, ended_at
        FROM sessions
    """)
    op.execute("DROP TABLE sessions")
    op.execute("ALTER TABLE sessions_new RENAME TO sessions")
    op.execute("CREATE INDEX idx_sessions_cell ON sessions (cell_id)")
    op.execute("CREATE INDEX idx_sessions_started_at ON sessions (started_at)")
    op.execute("PRAGMA foreign_keys = ON")
    with op.batch_alter_table("messages") as batch:
        batch.drop_column("cell_id")
        batch.drop_column("plmn")
