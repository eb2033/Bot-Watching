from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from db.crud import insert_alert, insert_auth_attempt, insert_command, insert_download, insert_session
from db.models import Alert, AuthAttempt, Base, Command, Download, Session
from parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, SessionConnectEvent, Alert as AlertEvent


@pytest.fixture()
def crud_db(tmp_path):
	database_path = tmp_path / "crud.sqlite3"
	engine = create_engine(f"sqlite+pysqlite:///{database_path}", future=True)
	Base.metadata.create_all(engine)
	SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()
		Base.metadata.drop_all(engine)
		engine.dispose()


def _session_event() -> SessionConnectEvent:
	return SessionConnectEvent(
		session_id="sess-001",
		eventid="cowrie.session.connect",
		timestamp=datetime.now(timezone.utc),
		src_ip="10.0.0.1",
		src_port=2222,
		dst_port=22,
		protocol="ssh",
		raw={},
	)


def _auth_event() -> AuthAttemptEvent:
	return AuthAttemptEvent(
		session_id="sess-001",
		eventid="cowrie.login.failed",
		timestamp=datetime.now(timezone.utc),
		src_ip="10.0.0.1",
		username="root",
		password="toor",
		success=False,
		raw={},
	)


def _command_event() -> CommandEvent:
	return CommandEvent(
		session_id="sess-001",
		eventid="cowrie.command.input",
		timestamp=datetime.now(timezone.utc),
		src_ip="10.0.0.1",
		input="cat /etc/passwd",
		raw={},
	)


def _download_event() -> DownloadEvent:
	return DownloadEvent(
		session_id="sess-001",
		eventid="cowrie.session.file_download",
		timestamp=datetime.now(timezone.utc),
		src_ip="10.0.0.1",
		url="https://example.com/payload.bin",
		filename="payload.bin",
		file_path="/tmp/payload.bin",
		sha256="a" * 64,
		raw={},
	)


def _alert_event() -> AlertEvent:
	return AlertEvent(
		session_id="sess-001",
		eventid="cowrie.alert",
		timestamp=datetime.now(timezone.utc),
		src_ip="10.0.0.1",
		raw={},
		rule_name="Suspicious Command",
		severity="High",
		details="Matched suspicious keyword 'passwd' in command: cat /etc/passwd",
	)


def test_insert_session_persists_row(crud_db):
	row = insert_session(crud_db, _session_event())
	crud_db.commit()

	saved_row = crud_db.get(Session, row.session_id)
	assert saved_row is not None
	assert saved_row.src_ip == "10.0.0.1"
	assert saved_row.protocol == "ssh"


def test_insert_auth_attempt_persists_row(crud_db):
	insert_session(crud_db, _session_event())
	row = insert_auth_attempt(crud_db, _auth_event())
	crud_db.commit()

	saved_row = crud_db.get(AuthAttempt, row.id)
	assert saved_row is not None
	assert saved_row.username == "root"
	assert saved_row.password == "toor"
	assert saved_row.success is False


def test_insert_command_persists_row(crud_db):
	insert_session(crud_db, _session_event())
	row = insert_command(crud_db, _command_event())
	crud_db.commit()

	saved_row = crud_db.get(Command, row.id)
	assert saved_row is not None
	assert saved_row.input == "cat /etc/passwd"


def test_insert_download_persists_row(crud_db):
	insert_session(crud_db, _session_event())
	row = insert_download(crud_db, _download_event())
	crud_db.commit()

	saved_row = crud_db.get(Download, row.id)
	assert saved_row is not None
	assert saved_row.url == "https://example.com/payload.bin"
	assert saved_row.filename == "payload.bin"
	assert saved_row.file_path == "/tmp/payload.bin"
	assert saved_row.sha256 == "a" * 64


def test_insert_alert_persists_row(crud_db):
	insert_session(crud_db, _session_event())
	row = insert_alert(
		crud_db,
		_alert_event(),
		rule_name="Suspicious Command",
		severity="High",
		details="Matched suspicious keyword 'passwd' in command: cat /etc/passwd",
	)
	crud_db.commit()

	saved_row = crud_db.get(Alert, row.id)
	assert saved_row is not None
	assert saved_row.rule_name == "Suspicious Command"
	assert saved_row.severity == "High"
	assert saved_row.details == "Matched suspicious keyword 'passwd' in command: cat /etc/passwd"


def test_insert_helpers_can_be_queried_together(crud_db):
	insert_session(crud_db, _session_event())
	insert_auth_attempt(crud_db, _auth_event())
	insert_command(crud_db, _command_event())
	insert_download(crud_db, _download_event())
	insert_alert(
		crud_db,
		_alert_event(),
		rule_name="Suspicious Command",
		severity="High",
		details="Matched suspicious keyword 'passwd' in command: cat /etc/passwd",
	)
	crud_db.commit()

	assert crud_db.scalar(select(func.count()).select_from(Session)) == 1
	assert crud_db.scalar(select(func.count()).select_from(AuthAttempt)) == 1
	assert crud_db.scalar(select(func.count()).select_from(Command)) == 1
	assert crud_db.scalar(select(func.count()).select_from(Download)) == 1
	assert crud_db.scalar(select(func.count()).select_from(Alert)) == 1