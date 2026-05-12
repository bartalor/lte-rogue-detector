"""sessions.cell_id nullable

Revision ID: c6921309ddf3
Revises: b449560ba86f
Create Date: 2026-05-12 11:48:53.839140

The sniffer does not yet extract E-UTRAN-CGI from S1AP InitialUEMessage, so
sessions created by the detector's sessionizer have no cell to point at. Make
cell_id nullable; we'll backfill once cell extraction lands.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c6921309ddf3"
down_revision: Union[str, Sequence[str], None] = "b449560ba86f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("sessions") as batch:
        batch.alter_column(
            "cell_id", existing_type=sa.Integer(), nullable=True
        )


def downgrade() -> None:
    with op.batch_alter_table("sessions") as batch:
        batch.alter_column(
            "cell_id", existing_type=sa.Integer(), nullable=False
        )
