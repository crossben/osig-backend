"""enterprise prices

Revision ID: 2a5a4ff5945d
Revises: c41f7e2a9b10
Create Date: 2026-10-11 15:03:24.380291

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2a5a4ff5945d'
down_revision: Union[str, None] = 'c41f7e2a9b10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Enterprise gets prices (still not sold online) so Yoon can grant and rank it. Keeps admin edits."""
    op.execute("""
        UPDATE plans SET prices = '{"XOF": {"month": 25000, "year": 250000}, "USD": {"month": 4900, "year": 49000}}'::jsonb
        WHERE slug = 'enterprise' AND (prices IS NULL OR prices = '{}'::jsonb)
    """)


def downgrade() -> None:
    pass  # leave prices in place: removing them would break grants already made in Yoon
