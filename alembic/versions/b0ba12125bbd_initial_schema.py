"""initial schema

Revision ID: b0ba12125bbd
Revises:
Create Date: 2026-05-11 14:24:19.341608

Data model for the LTE rogue base station detector.

    cells     : one row per observed (PLMN, E-CGI) cell.
    sessions  : one row per UE attach / TAU procedure on a given cell. Groups
                the S1AP/NAS messages belonging to a single UE-network
                procedure, keyed by the S1AP eNB-UE-S1AP-ID (and the
                MME-UE-S1AP-ID once allocated).
    messages  : one row per decoded NAS message, with the IEs the detection
                rules care about extracted as columns.
    alerts    : one row per detection-rule hit, linking back to the session
                and the offending message.

Indexes are chosen for the queries the detection rules actually issue. See
docs/queries.md for the EXPLAIN QUERY PLAN verification.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "b0ba12125bbd"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cells",
        sa.Column("cell_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("plmn", sa.Text, nullable=False),
        sa.Column("enb_id", sa.Integer, nullable=False),
        sa.Column("e_cgi", sa.Integer, nullable=False),
        sa.Column("tac", sa.Integer),
        sa.Column("first_seen", sa.Text, nullable=False),
        sa.Column("last_seen", sa.Text, nullable=False),
        sa.UniqueConstraint("plmn", "e_cgi", name="uq_cells_plmn_ecgi"),
    )

    op.create_table(
        "sessions",
        sa.Column("session_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "cell_id",
            sa.Integer,
            sa.ForeignKey("cells.cell_id"),
            nullable=False,
        ),
        sa.Column("enb_ue_s1ap_id", sa.Integer, nullable=False),
        sa.Column("mme_ue_s1ap_id", sa.Integer),
        sa.Column("imsi", sa.Text),
        sa.Column("guti", sa.Text),
        sa.Column("tmsi", sa.Text),
        sa.Column("started_at", sa.Text, nullable=False),
        sa.Column("ended_at", sa.Text),
        sa.UniqueConstraint(
            "cell_id",
            "enb_ue_s1ap_id",
            "started_at",
            name="uq_sessions_cell_enbueid_started",
        ),
    )

    op.create_table(
        "messages",
        sa.Column("message_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.Integer,
            sa.ForeignKey("sessions.session_id"),
            nullable=False,
        ),
        sa.Column("ts", sa.Text, nullable=False),
        sa.Column("direction", sa.Text, nullable=False),
        sa.Column("nas_msg_type", sa.Text, nullable=False),
        sa.Column("identity_type", sa.Text),
        sa.Column("eea_selected", sa.Integer),
        sa.Column("eia_selected", sa.Integer),
        sa.Column("ue_eea_caps", sa.Integer),
        sa.Column("ue_eia_caps", sa.Integer),
        sa.Column("emm_cause", sa.Integer),
        sa.Column("raw_pcap_offset", sa.Integer),
        sa.Column("raw_frame_number", sa.Integer),
        sa.CheckConstraint(
            "direction IN ('UL', 'DL')",
            name="ck_messages_direction",
        ),
    )

    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.Integer,
            sa.ForeignKey("sessions.session_id"),
            nullable=False,
        ),
        sa.Column(
            "trigger_message_id",
            sa.Integer,
            sa.ForeignKey("messages.message_id"),
        ),
        sa.Column("rule_name", sa.Text, nullable=False),
        sa.Column("severity", sa.Integer, nullable=False),
        sa.Column("detail", sa.Text),
        sa.Column(
            "created_at",
            sa.Text,
            nullable=False,
            server_default=sa.text("(datetime('now'))"),
        ),
        sa.CheckConstraint(
            "severity BETWEEN 1 AND 10",
            name="ck_alerts_severity_range",
        ),
    )

    # Indexes match the queries the detection rules issue:
    #   1. messages in a session, in order               -> (session_id, ts)
    #   2. messages of a given NAS type within a session -> (session_id, nas_msg_type)
    #   3. sessions on a given cell                      -> (cell_id)
    #   4. sessions in a time window                     -> (started_at)
    #   5. alerts for a session / by rule                -> (session_id), (rule_name)
    op.create_index(
        "idx_messages_session_ts", "messages", ["session_id", "ts"]
    )
    op.create_index(
        "idx_messages_session_type",
        "messages",
        ["session_id", "nas_msg_type"],
    )
    op.create_index("idx_sessions_cell", "sessions", ["cell_id"])
    op.create_index("idx_sessions_started_at", "sessions", ["started_at"])
    op.create_index("idx_alerts_session", "alerts", ["session_id"])
    op.create_index("idx_alerts_rule", "alerts", ["rule_name"])


def downgrade() -> None:
    op.drop_index("idx_alerts_rule", table_name="alerts")
    op.drop_index("idx_alerts_session", table_name="alerts")
    op.drop_index("idx_sessions_started_at", table_name="sessions")
    op.drop_index("idx_sessions_cell", table_name="sessions")
    op.drop_index("idx_messages_session_type", table_name="messages")
    op.drop_index("idx_messages_session_ts", table_name="messages")
    op.drop_table("alerts")
    op.drop_table("messages")
    op.drop_table("sessions")
    op.drop_table("cells")
