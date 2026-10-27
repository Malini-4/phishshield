"""initial migration

Revision ID: 0001_initial
Revises: 
Create Date: 2026-10-10 11:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'investigations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('type', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('verdict', sa.String(length=30), nullable=False),
        sa.Column('display_label', sa.String(length=80), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('input_display', sa.Text(), nullable=False),
        sa.Column('input_hash', sa.String(length=64), nullable=False),
        sa.Column('analysis_version', sa.String(length=20), nullable=False),
        sa.Column('model_version', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('result_json', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_investigations_created_at', 'investigations', ['created_at'])
    op.create_index('ix_investigations_type', 'investigations', ['type'])
    op.create_index('ix_investigations_verdict', 'investigations', ['verdict'])
    op.create_index('ix_investigations_type_verdict', 'investigations', ['type', 'verdict'])
    op.create_index('ix_investigations_created_type', 'investigations', ['created_at', 'type'])

    op.create_table(
        'evidence_items',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=False),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('detail', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidence_items_investigation_id', 'evidence_items', ['investigation_id'])

    op.create_table(
        'checks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_checks_investigation_id', 'checks', ['investigation_id'])

    op.create_table(
        'url_details',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('original_url', sa.Text(), nullable=False),
        sa.Column('registrable_domain', sa.String(length=200), nullable=True),
        sa.Column('scheme', sa.String(length=10), nullable=True),
        sa.Column('host', sa.String(length=500), nullable=True),
        sa.Column('path', sa.Text(), nullable=True),
        sa.Column('model_score', sa.Float(), nullable=True),
        sa.Column('model_band', sa.String(length=20), nullable=True),
        sa.Column('reputation_results', sa.JSON(), nullable=True),
        sa.Column('rule_hits', sa.JSON(), nullable=True),
        sa.Column('features_summary', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id')
    )

    op.create_table(
        'apk_details',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('package_name', sa.String(length=300), nullable=True),
        sa.Column('app_label', sa.String(length=200), nullable=True),
        sa.Column('version_name', sa.String(length=50), nullable=True),
        sa.Column('version_code', sa.String(length=20), nullable=True),
        sa.Column('sha256', sa.String(length=64), nullable=True),
        sa.Column('md5', sa.String(length=32), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('permissions', sa.JSON(), nullable=True),
        sa.Column('sensitive_permissions', sa.JSON(), nullable=True),
        sa.Column('embedded_urls', sa.JSON(), nullable=True),
        sa.Column('min_sdk', sa.String(length=10), nullable=True),
        sa.Column('target_sdk', sa.String(length=10), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id')
    )

    op.create_table(
        'sms_details',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('sender', sa.String(length=30), nullable=True),
        sa.Column('sender_state', sa.String(length=20), nullable=True),
        sa.Column('message_hash', sa.String(length=64), nullable=True),
        sa.Column('redacted_text', sa.Text(), nullable=True),
        sa.Column('extracted_urls', sa.JSON(), nullable=True),
        sa.Column('message_length', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id')
    )

    op.create_table(
        'screenshot_details',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('investigation_id', sa.String(length=36), nullable=False),
        sa.Column('file_hash', sa.String(length=64), nullable=True),
        sa.Column('file_size_bytes', sa.Integer(), nullable=True),
        sa.Column('image_width', sa.Integer(), nullable=True),
        sa.Column('image_height', sa.Integer(), nullable=True),
        sa.Column('ocr_engine', sa.String(length=30), nullable=True),
        sa.Column('ocr_confidence', sa.Float(), nullable=True),
        sa.Column('extracted_fields', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('investigation_id')
    )

    op.create_table(
        'reputation_feed_entries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('url', sa.Text(), nullable=True),
        sa.Column('fetched_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('entry_meta', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_reputation_feed_entries_source', 'reputation_feed_entries', ['source'])
    op.create_index('ix_feed_source_hash', 'reputation_feed_entries', ['source', 'url_hash'])

    op.create_table(
        'feed_status',
        sa.Column('source', sa.String(length=30), nullable=False),
        sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('record_count', sa.Integer(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('source')
    )

    op.create_table(
        'app_meta',
        sa.Column('key', sa.String(length=50), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('key')
    )


def downgrade() -> None:
    op.drop_table('app_meta')
    op.drop_table('feed_status')
    op.drop_table('reputation_feed_entries')
    op.drop_table('screenshot_details')
    op.drop_table('sms_details')
    op.drop_table('apk_details')
    op.drop_table('url_details')
    op.drop_table('checks')
    op.drop_table('evidence_items')
    op.drop_table('investigations')
