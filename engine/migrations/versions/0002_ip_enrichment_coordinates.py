"""Add GeoLite2 latitude/longitude to ip_enrichment

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
	with op.batch_alter_table("ip_enrichment") as batch_op:
		batch_op.add_column(sa.Column("latitude", sa.Float(), nullable=True))
		batch_op.add_column(sa.Column("longitude", sa.Float(), nullable=True))


def downgrade() -> None:
	with op.batch_alter_table("ip_enrichment") as batch_op:
		batch_op.drop_column("longitude")
		batch_op.drop_column("latitude")
