from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.engine import Connection, Engine

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"

# Schema as Base.metadata.create_all() built it before latitude/longitude
# were added to ip_enrichment.
BASELINE_REVISION = "0001"
# Adds ip_enrichment.latitude/longitude.
COORDINATES_REVISION = "0002"
HEAD_REVISION = COORDINATES_REVISION


def _alembic_config(connection: Connection) -> Config:
	config = Config()
	config.set_main_option("script_location", str(MIGRATIONS_DIR))
	config.attributes["connection"] = connection
	return config


def _legacy_revision(connection: Connection) -> str | None:
	"""Revision matching a database built by create_all() before Alembic.

	Returns None for a database Alembic already manages, or an empty one.
	"""
	inspector = inspect(connection)
	table_names = set(inspector.get_table_names())
	if "alembic_version" in table_names or "sessions" not in table_names:
		return None

	ip_columns = {column["name"] for column in inspector.get_columns("ip_enrichment")}
	if {"latitude", "longitude"} <= ip_columns:
		return COORDINATES_REVISION
	return BASELINE_REVISION


def upgrade_to_head(engine: Engine) -> None:
	with engine.begin() as connection:
		config = _alembic_config(connection)

		legacy_revision = _legacy_revision(connection)
		if legacy_revision is not None:
			logger.warning(
				"Found tables created before schema migrations; stamping as revision %s",
				legacy_revision,
			)
			command.stamp(config, legacy_revision)

		command.upgrade(config, "head")
