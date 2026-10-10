"""ip and organization target types

Revision ID: adbc86924a1e
Revises: d9bef6c91fa5
Create Date: 2026-10-10 21:08:30.787104

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'adbc86924a1e'
down_revision: Union[str, None] = 'd9bef6c91fa5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Postgres can't add enum values inside a transaction block on older versions;
    # autocommit keeps this portable. Enum labels are the Python member names.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE targettype ADD VALUE IF NOT EXISTS 'IP'")
        op.execute("ALTER TYPE targettype ADD VALUE IF NOT EXISTS 'ORGANIZATION'")


def downgrade() -> None:
    # Postgres can't drop enum values; remove scans/watches using them first,
    # then the values simply stay unused.
    op.execute("DELETE FROM scans WHERE target_type IN ('IP', 'ORGANIZATION')")
    op.execute("DELETE FROM watches WHERE target_type IN ('IP', 'ORGANIZATION')")
