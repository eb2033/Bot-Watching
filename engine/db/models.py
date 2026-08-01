from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from engine.db.sanitization import sanitize_text

_SKIP_SANITIZATION_FIELDS = {"id", "session_id", "src_ip", "severity", "rule_name"}


class Base(DeclarativeBase):
	pass


class Session(Base):
	__tablename__ = "sessions"

	session_id: Mapped[str] = mapped_column(String(128), primary_key=True)
	src_ip: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
	start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
	end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
	protocol: Mapped[str] = mapped_column(String(32), nullable=False)

	auth_attempts: Mapped[list[AuthAttempt]] = relationship(back_populates="session", cascade="all, delete-orphan")
	commands: Mapped[list[Command]] = relationship(back_populates="session", cascade="all, delete-orphan")
	downloads: Mapped[list[Download]] = relationship(back_populates="session", cascade="all, delete-orphan")
	alerts: Mapped[list[Alert]] = relationship(back_populates="session", cascade="all, delete-orphan")
 
class IPEnrichment(Base):
	__tablename__ = "ip_enrichment"
	src_ip: Mapped[str] = mapped_column(String(45), primary_key=True)
	country: Mapped[str | None] = mapped_column(String(64), nullable=True)
	city: Mapped[str | None] = mapped_column(String(128), nullable=True)
	asn: Mapped[str | None] = mapped_column(String(64), nullable=True)
	org: Mapped[str | None] = mapped_column(String(255), nullable=True)
	latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
	longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
	enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuthAttempt(Base):
	__tablename__ = "auth_attempts"
	__table_args__ = (
		UniqueConstraint("session_id", "timestamp", "username", "password", name="uq_auth_attempt_dedup"),
		Index("ix_auth_attempts_timestamp", "timestamp"),
	)

	id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
	session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False)
	username: Mapped[str] = mapped_column(String(255), nullable=False)
	password: Mapped[str] = mapped_column(String(255), nullable=False)
	success: Mapped[bool] = mapped_column(Boolean, nullable=False)
	timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

	session: Mapped[Session] = relationship(back_populates="auth_attempts")


class Command(Base):
	__tablename__ = "commands"
	__table_args__ = (
		UniqueConstraint("session_id", "timestamp", "input", name="uq_command_dedup"),
		Index("ix_commands_timestamp", "timestamp"),
	)

	id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
	session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False)
	input: Mapped[str] = mapped_column(String(4096), nullable=False)
	timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

	session: Mapped[Session] = relationship(back_populates="commands")


class Download(Base):
	__tablename__ = "downloads"
	__table_args__ = (
		UniqueConstraint("session_id", "timestamp", "url", "sha256", name="uq_download_dedup"),
		Index("ix_downloads_timestamp", "timestamp"),
	)

	id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
	session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False)
	url: Mapped[str] = mapped_column(String(2048), nullable=False)
	sha256: Mapped[str] = mapped_column(String(64), nullable=False)
	filename: Mapped[str] = mapped_column(String(255), nullable=False)
	file_path: Mapped[str] = mapped_column(String(4096), nullable=False)
	timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

	session: Mapped[Session] = relationship(back_populates="downloads")


class Alert(Base):
	__tablename__ = "alerts"
	__table_args__ = (
		UniqueConstraint("session_id", "timestamp", "rule_name", name="uq_alert_dedup"),
		Index("ix_alerts_timestamp", "timestamp"),
	)

	id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
	session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False)
	rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
	severity: Mapped[str] = mapped_column(String(32), nullable=False)
	details: Mapped[str] = mapped_column(String(4096), nullable=False)
	timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

	session: Mapped[Session] = relationship(back_populates="alerts")


def _sanitize_model_strings(target: Any) -> None:
	mapper = target.__mapper__
	for column in mapper.columns:
		if not isinstance(column.type, String):
			continue
		if column.key in _SKIP_SANITIZATION_FIELDS:
			continue

		value = getattr(target, column.key, None)
		if value is None:
			continue

		sanitized_value = sanitize_text(value=value, max_length=column.type.length)
		setattr(target, column.key, sanitized_value)
  



@event.listens_for(Base, "before_insert", propagate=True)
def _before_insert_sanitize_strings(mapper, connection, target) -> None:
	_sanitize_model_strings(target)


@event.listens_for(Base, "before_update", propagate=True)
def _before_update_sanitize_strings(mapper, connection, target) -> None:
	_sanitize_model_strings(target)
