"""Baseline schema, as create_all() built it before IP coordinates

Revision ID: 0001
Revises:
Create Date: 2026-10-07
"""
from alembic import op
import sqlalchemy as sa


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
	op.create_table(
		"sessions",
		sa.Column("session_id", sa.String(length=128), nullable=False),
		sa.Column("src_ip", sa.String(length=45), nullable=False),
		sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
		sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
		sa.Column("protocol", sa.String(length=32), nullable=False),
		sa.PrimaryKeyConstraint("session_id"),
	)
	op.create_index("ix_sessions_src_ip", "sessions", ["src_ip"])
	op.create_index("ix_sessions_start_time", "sessions", ["start_time"])

	op.create_table(
		"ip_enrichment",
		sa.Column("src_ip", sa.String(length=45), nullable=False),
		sa.Column("country", sa.String(length=64), nullable=True),
		sa.Column("city", sa.String(length=128), nullable=True),
		sa.Column("asn", sa.String(length=64), nullable=True),
		sa.Column("org", sa.String(length=255), nullable=True),
		sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=False),
		sa.PrimaryKeyConstraint("src_ip"),
	)

	op.create_table(
		"auth_attempts",
		sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
		sa.Column("session_id", sa.String(length=128), nullable=False),
		sa.Column("username", sa.String(length=255), nullable=False),
		sa.Column("password", sa.String(length=255), nullable=False),
		sa.Column("success", sa.Boolean(), nullable=False),
		sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
		sa.ForeignKeyConstraint(["session_id"], ["sessions.session_id"], ondelete="CASCADE"),
		sa.PrimaryKeyConstraint("id"),
		sa.UniqueConstraint("session_id", "timestamp", "username", "password", name="uq_auth_attempt_dedup"),
	)
	op.create_index("ix_auth_attempts_timestamp", "auth_attempts", ["timestamp"])

	op.create_table(
		"commands",
		sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
		sa.Column("session_id", sa.String(length=128), nullable=False),
		sa.Column("input", sa.String(length=4096), nullable=False),
		sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
		sa.ForeignKeyConstraint(["session_id"], ["sessions.session_id"], ondelete="CASCADE"),
		sa.PrimaryKeyConstraint("id"),
		sa.UniqueConstraint("session_id", "timestamp", "input", name="uq_command_dedup"),
	)
	op.create_index("ix_commands_timestamp", "commands", ["timestamp"])

	op.create_table(
		"downloads",
		sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
		sa.Column("session_id", sa.String(length=128), nullable=False),
		sa.Column("url", sa.String(length=2048), nullable=False),
		sa.Column("sha256", sa.String(length=64), nullable=False),
		sa.Column("filename", sa.String(length=255), nullable=False),
		sa.Column("file_path", sa.String(length=4096), nullable=False),
		sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
		sa.ForeignKeyConstraint(["session_id"], ["sessions.session_id"], ondelete="CASCADE"),
		sa.PrimaryKeyConstraint("id"),
		sa.UniqueConstraint("session_id", "timestamp", "url", "sha256", name="uq_download_dedup"),
	)
	op.create_index("ix_downloads_timestamp", "downloads", ["timestamp"])

	op.create_table(
		"alerts",
		sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
		sa.Column("session_id", sa.String(length=128), nullable=False),
		sa.Column("rule_name", sa.String(length=255), nullable=False),
		sa.Column("severity", sa.String(length=32), nullable=False),
		sa.Column("details", sa.String(length=4096), nullable=False),
		sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
		sa.ForeignKeyConstraint(["session_id"], ["sessions.session_id"], ondelete="CASCADE"),
		sa.PrimaryKeyConstraint("id"),
		sa.UniqueConstraint("session_id", "timestamp", "rule_name", name="uq_alert_dedup"),
	)
	op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])


def downgrade() -> None:
	op.drop_table("alerts")
	op.drop_table("downloads")
	op.drop_table("commands")
	op.drop_table("auth_attempts")
	op.drop_table("ip_enrichment")
	op.drop_table("sessions")
