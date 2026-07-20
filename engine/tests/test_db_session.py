from __future__ import annotations

import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text


ENGINE_DIR = Path(__file__).resolve().parents[1]
ENGINE_DIR_STR = str(ENGINE_DIR)

if ENGINE_DIR_STR not in sys.path:
	sys.path.insert(0, ENGINE_DIR_STR)


def _load_session_module(monkeypatch, tmp_path, database_name: str):
	database_path = tmp_path / f"{database_name}.db"
	monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")

	config_module = importlib.import_module("config")
	importlib.reload(config_module)

	session_module = importlib.import_module("db.session")
	return importlib.reload(session_module)


def test_engine_can_open_connection(monkeypatch, tmp_path):
	session_module = _load_session_module(monkeypatch, tmp_path, "connection")
	assert session_module.engine is None

	with session_module.get_engine().connect() as connection:
		assert connection.scalar(text("SELECT 1")) == 1
	assert session_module.engine is not None


def test_get_db_session_persists_rows(monkeypatch, tmp_path):
	session_module = _load_session_module(monkeypatch, tmp_path, "persist")

	from db.models import Base, Session

	Base.metadata.create_all(session_module.get_engine())

	with session_module.get_db_session() as db:
		db.add(
			Session(
				session_id="sess-001",
				src_ip="10.0.0.1",
				start_time=datetime.now(timezone.utc),
				protocol="ssh",
			)
		)

	with session_module.get_db_session() as db:
		saved_session = db.get(Session, "sess-001")
		assert saved_session is not None
		assert saved_session.src_ip == "10.0.0.1"
		assert saved_session.protocol == "ssh"


def test_get_db_session_rolls_back_on_error(monkeypatch, tmp_path):
	session_module = _load_session_module(monkeypatch, tmp_path, "rollback")

	try:
		with session_module.get_db_session() as db:
			assert db.in_transaction() is False
			raise RuntimeError("boom")
	except RuntimeError:
		pass

	with session_module.get_engine().connect() as connection:
		assert connection.scalar(text("SELECT 1")) == 1