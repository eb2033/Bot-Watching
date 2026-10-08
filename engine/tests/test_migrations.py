from __future__ import annotations

from datetime import datetime, timezone

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from engine.db.migrate import HEAD_REVISION, upgrade_to_head
from engine.db.models import Base


def _sqlite_engine(tmp_path, name: str):
	return create_engine(f"sqlite+pysqlite:///{tmp_path / name}.sqlite3", future=True)


def _current_revision(engine) -> str | None:
	with engine.connect() as connection:
		return MigrationContext.configure(connection).get_current_revision()


def _ip_enrichment_columns(engine) -> set[str]:
	return {column["name"] for column in inspect(engine).get_columns("ip_enrichment")}


def test_fresh_database_migrates_to_match_models(tmp_path):
	engine = _sqlite_engine(tmp_path, "fresh")

	upgrade_to_head(engine)

	assert _current_revision(engine) == HEAD_REVISION
	with engine.connect() as connection:
		diff = compare_metadata(MigrationContext.configure(connection), Base.metadata)
	assert diff == []


def test_upgrade_is_idempotent(tmp_path):
	engine = _sqlite_engine(tmp_path, "idempotent")

	upgrade_to_head(engine)
	upgrade_to_head(engine)

	assert _current_revision(engine) == HEAD_REVISION


def test_legacy_create_all_database_is_stamped_and_keeps_data(tmp_path):
	engine = _sqlite_engine(tmp_path, "legacy_current")
	Base.metadata.create_all(engine)
	with engine.begin() as connection:
		connection.execute(
			text(
				"INSERT INTO sessions (session_id, src_ip, start_time, protocol) "
				"VALUES ('sess-legacy', '10.0.0.1', :start_time, 'ssh')"
			),
			{"start_time": datetime.now(timezone.utc)},
		)

	upgrade_to_head(engine)

	assert _current_revision(engine) == HEAD_REVISION
	with engine.connect() as connection:
		assert connection.scalar(text("SELECT count(*) FROM sessions")) == 1


def test_legacy_database_without_coordinates_gets_them_added(tmp_path):
	# A database built by create_all() before latitude/longitude existed:
	# create_all() never alters existing tables, so these columns would be
	# missing forever without a migration.
	engine = _sqlite_engine(tmp_path, "legacy_pre_coords")
	Base.metadata.create_all(engine)
	with engine.begin() as connection:
		connection.execute(text("ALTER TABLE ip_enrichment DROP COLUMN latitude"))
		connection.execute(text("ALTER TABLE ip_enrichment DROP COLUMN longitude"))
	assert "latitude" not in _ip_enrichment_columns(engine)

	upgrade_to_head(engine)

	assert {"latitude", "longitude"} <= _ip_enrichment_columns(engine)
	assert _current_revision(engine) == HEAD_REVISION
