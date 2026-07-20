from __future__ import annotations

import json

from engine.listener import CowrieLogListener, parse_cowrie_line
from engine.main import EngineProcessor
from engine.parser.schemas import CommandEvent


def _write_log_file(path, lines: list[dict]) -> None:
	path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")


def test_listener_reads_five_lines_and_trims_file(tmp_path):
	log_path = tmp_path / "cowrie.json"
	_write_log_file(
		log_path,
		[{"eventid": f"event-{index}", "line": index} for index in range(6)],
	)

	listener = CowrieLogListener(log_path=log_path, batch_size=5)
	batch = listener.read_batch()

	assert len(batch) == 5

	listener.discard_processed(len(batch))
	remaining_lines = log_path.read_text(encoding="utf-8").splitlines()
	assert len(remaining_lines) == 1
	assert json.loads(remaining_lines[0])["line"] == 5


def test_parse_cowrie_line_maps_known_event_types():
	parsed = parse_cowrie_line(
		json.dumps(
			{
				"eventid": "cowrie.command.input",
				"session": "sess-1",
				"timestamp": "2026-07-08T22:40:57.992078Z",
				"src_ip": "10.10.10.20",
				"input": "cat /etc/passwd",
			}
		)
	)

	assert parsed is not None
	assert isinstance(parsed, CommandEvent)
	assert parsed.session_id == "sess-1"
	assert parsed.input == "cat /etc/passwd"


def test_processor_persists_session_and_alerts(tmp_path, monkeypatch):
	database_path = tmp_path / "engine.sqlite3"
	monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")

	from engine.db.models import Alert, Base, Command, Session
	from engine.db.session import get_engine, get_db_session
	from engine.listener import parse_cowrie_line

	engine = get_engine()
	Base.metadata.create_all(engine)

	processor = EngineProcessor()
	connect = parse_cowrie_line(
		json.dumps(
			{
				"eventid": "cowrie.session.connect",
				"session": "sess-2",
				"timestamp": "2026-07-08T22:40:38.158655Z",
				"src_ip": "10.10.10.20",
				"src_port": 2222,
				"dst_port": 22,
				"protocol": "ssh",
			}
		)
	)
	assert connect is not None
	command = parse_cowrie_line(
		json.dumps(
			{
				"eventid": "cowrie.command.input",
				"session": "sess-2",
				"timestamp": "2026-07-08T22:40:39.158655Z",
				"src_ip": "10.10.10.20",
				"input": "cat /etc/passwd",
				"protocol": "ssh",
			}
		)
	)
	assert command is not None

	with get_db_session() as db:
		processor.process_event(db, connect)
		processor.process_event(db, command)
		db.flush()

	with get_db_session() as db:
		assert db.get(Session, "sess-2") is not None
		assert db.query(Command).count() == 1
		assert db.query(Alert).count() == 1


def test_processor_ignores_duplicate_events(tmp_path, monkeypatch):
	database_path = tmp_path / "engine.sqlite3"
	monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")

	from engine.db.models import Alert, Base, Command
	from engine.db.session import get_engine, get_db_session
	from engine.listener import parse_cowrie_line

	engine = get_engine()
	Base.metadata.create_all(engine)

	processor = EngineProcessor()
	event = parse_cowrie_line(
		json.dumps(
			{
				"eventid": "cowrie.command.input",
				"session": "sess-3",
				"timestamp": "2026-07-08T22:40:39.158655Z",
				"src_ip": "10.10.10.20",
				"input": "cat /etc/passwd",
				"protocol": "ssh",
			}
		)
	)
	assert event is not None

	with get_db_session() as db:
		processor.process_event(db, event)
		processor.process_event(db, event)

	with get_db_session() as db:
		assert db.query(Command).count() == 1
		assert db.query(Alert).count() == 1