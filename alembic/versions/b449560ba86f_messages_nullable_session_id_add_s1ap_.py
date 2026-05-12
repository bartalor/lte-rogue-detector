"""messages: nullable session_id, add s1ap ids

Revision ID: b449560ba86f
Revises: b0ba12125bbd
Create Date: 2026-05-12 11:17:48.980999

The C++ sniffer inserts one row per decoded NAS message but does not own
sessionization (no per-UE state, no cell-info parsing yet). Sessions are built
later by the Python detector, which then UPDATEs messages.session_id. To make
that flow work:

  - messages.session_id becomes nullable (sniffer writes NULL).
  - messages gains enb_ue_s1ap_id / mme_ue_s1ap_id columns so the detector can
    group rows into sessions without going back to the raw pcap.

The (enb_ue_s1ap_id, ts) index supports the detector's grouping query.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b449560ba86f"
down_revision: Union[str, Sequence[str], None] = "b0ba12125bbd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("messages") as batch:
        batch.alter_column("session_id", existing_type=sa.Integer(), nullable=True)
        batch.add_column(sa.Column("enb_ue_s1ap_id", sa.Integer))
        batch.add_column(sa.Column("mme_ue_s1ap_id", sa.Integer))
    op.create_index(
        "idx_messages_enb_ue_s1ap_id",
        "messages",
        ["enb_ue_s1ap_id", "ts"],
    )


def downgrade() -> None:
    op.drop_index("idx_messages_enb_ue_s1ap_id", table_name="messages")
    with op.batch_alter_table("messages") as batch:
        batch.drop_column("mme_ue_s1ap_id")
        batch.drop_column("enb_ue_s1ap_id")
        batch.alter_column("session_id", existing_type=sa.Integer(), nullable=False)
