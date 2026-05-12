"""messages: partial index for unsessionized rows

Revision ID: d1a7f3e2c9b4
Revises: c6921309ddf3
Create Date: 2026-05-12 11:13:00.000000

The sessionizer scans `WHERE session_id IS NULL ORDER BY ts, message_id` to
find rows the sniffer has written but the detector has not yet grouped into
sessions. Without a matching index this is O(all messages); with a partial
index on (ts, message_id) WHERE session_id IS NULL it is O(unsessionized),
and sessionized rows fall out of the index automatically.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "d1a7f3e2c9b4"
down_revision: Union[str, Sequence[str], None] = "c6921309ddf3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX idx_messages_unsessionized "
        "ON messages (ts, message_id) "
        "WHERE session_id IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX idx_messages_unsessionized")
