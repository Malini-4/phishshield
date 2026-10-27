"""
Migration 0002: Add user_id to investigations and create users table.
Safe incremental migration that preserves all existing records.
Existing records get user_id = NULL (they remain accessible to any authenticated user).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0002_add_users_and_user_id'
down_revision: Union[str, None] = '0001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()

    # Create users table if not already created
    if 'users' not in tables:
        op.create_table(
            'users',
            sa.Column('id', sa.String(length=36), nullable=False),
            sa.Column('email', sa.String(length=255), nullable=False),
            sa.Column('full_name', sa.String(length=200), nullable=False),
            sa.Column('hashed_password', sa.Text(), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('email'),
        )
        op.create_index('ix_users_email', 'users', ['email'])

    # Add nullable user_id to investigations (existing records get NULL)
    inv_cols = [c['name'] for c in insp.get_columns('investigations')]
    if 'user_id' not in inv_cols:
        op.add_column(
            'investigations',
            sa.Column('user_id', sa.String(length=36), nullable=True)
        )
        op.create_index('ix_investigations_user_id', 'investigations', ['user_id'])
        op.create_index('ix_investigations_user_created', 'investigations', ['user_id', 'created_at'])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    tables = insp.get_table_names()
    if 'investigations' in tables:
        inv_indexes = [idx['name'] for idx in insp.get_indexes('investigations')]
        if 'ix_investigations_user_created' in inv_indexes:
            op.drop_index('ix_investigations_user_created', 'investigations')
        if 'ix_investigations_user_id' in inv_indexes:
            op.drop_index('ix_investigations_user_id', 'investigations')
    if 'users' in tables:
        op.drop_table('users')
