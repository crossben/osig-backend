"""plan limits: identities and household

Data only: adds the `identities` and `household` limit keys to existing plan
rows (keeps any value an admin already set).

Revision ID: c41f7e2a9b10
Revises: 27483116bd40
Create Date: 2026-10-11 15:00:00

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'c41f7e2a9b10'
down_revision: Union[str, None] = '27483116bd40'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULTS = {"free": (3, 0), "pro": (10, 5), "enterprise": (25, 10)}


def upgrade() -> None:
    for slug, (identities, household) in DEFAULTS.items():
        op.execute(
            "UPDATE plans SET limits = "
            f"jsonb_build_object('identities', {identities}, 'household', {household}) || COALESCE(limits, '{{}}'::jsonb) "
            f"WHERE slug = '{slug}'"
        )


def downgrade() -> None:
    op.execute("UPDATE plans SET limits = limits - 'identities' - 'household'")
