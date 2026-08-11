from __future__ import annotations

import json

from engine.listener import CowrieLogListener, parse_cowrie_line
from engine.main import EngineProcessor
from engine.parser.schemas import CommandEvent


def _write_log_file(path, lines: list[dict]) -> None:
	path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")


def test_listener_reads_five_lines_then_advances_to_next_batch(tmp_path):
	log_path = tmp_path / "cowrie.json"
	_write_log_file(
		log_path,
		[{"eventid": f"event-{index}", "line": index} for index in range(6)],
	)

	listener = CowrieLogListener(log_path=log_path, batch_size=5)
	batch = listener.read_batch()
	assert len(batch) == 5

	listener.discard_processed(len(batch))

	# File is untouched; only the listener's read cursor advances.
	assert len(log_path.read_text(encoding="utf-8").splitlines()) == 6
	next_batch = listener.read_batch()
	assert len(next_batch) == 1
	assert json.loads(next_batch[0])["line"] == 5


def test_listener_does_not_lose_lines_appended_after_read_batch(tmp_path):
	# Guards against reintroducing a truncate-based discard: a writer
	# appending mid-batch must not be able to lose data.
	log_path = tmp_path / "cowrie.json"
	_write_log_file(log_path, [{"eventid": "first", "line": 0}])

	listener = CowrieLogListener(log_path=log_path, batch_size=5)
	batch = listener.read_batch()
	assert len(batch) == 1

	# Simulate a concurrent writer appending mid-batch.
	with log_path.open("a", encoding="utf-8") as f:
		f.write(json.dumps({"eventid": "second", "line": 1}) + "\n")

	listener.discard_processed(len(batch))

	next_batch = listener.read_batch()
	assert len(next_batch) == 1
	assert json.loads(next_batch[0])["line"] == 1


def test_listener_resumes_after_log_rotation(tmp_path):
	# Cowrie rotates cowrie.json (rename away, recreate) in any long-running
	# deployment. The stored byte offset then points past the end of the new,
	# smaller file - without rotation detection every later poll silently
	# returns nothing and ingestion stops for good.
	log_path = tmp_path / "cowrie.json"
	_write_log_file(log_path, [{"eventid": "old", "line": index} for index in range(6)])

	listener = CowrieLogListener(log_path=log_path, batch_size=5)
	listener.discard_processed(len(listener.read_batch()))
	listener.discard_processed(len(listener.read_batch()))

	log_path.rename(tmp_path / "cowrie.json.1")
	_write_log_file(log_path, [{"eventid": "new", "line": index} for index in range(3)])

	batch = listener.read_batch()
	listener.discard_processed(len(batch))

	assert [json.loads(line)["line"] for line in batch] == [0, 1, 2]
	assert all(json.loads(line)["eventid"] == "new" for line in batch)


def test_listener_resumes_after_log_truncated_in_place(tmp_path):
	log_path = tmp_path / "cowrie.json"
	_write_log_file(log_path, [{"eventid": "old", "line": index} for index in range(6)])

	listener = CowrieLogListener(log_path=log_path, batch_size=5)
	listener.discard_processed(len(listener.read_batch()))
	listener.discard_processed(len(listener.read_batch()))

	# Truncate + rewrite in place: same inode, smaller than the stored offset.
	_write_log_file(log_path, [{"eventid": "fresh", "line": 99}])

	batch = listener.read_batch()

	assert len(batch) == 1
	assert json.loads(batch[0])["line"] == 99


def test_listener_ignores_missing_log_file(tmp_path):
	listener = CowrieLogListener(log_path=tmp_path / "does-not-exist.json", batch_size=5)

	assert listener.read_batch() == []


def test_parse_cowrie_line_skips_malformed_events():
	# A known eventid missing fields its builder requires must not raise:
	# run_forever retries failed batches, so one bad line would otherwise
	# stall ingestion permanently instead of crashing loudly.
	missing_field = parse_cowrie_line(
		json.dumps(
			{
				"eventid": "cowrie.session.connect",
				"session": "sess-bad",
				"timestamp": "2026-07-08T22:40:38.158655Z",
				"src_ip": "10.10.10.20",
				"protocol": "ssh",
			}
		)
	)
	assert missing_field is None

	assert parse_cowrie_line("12345") is None
	assert parse_cowrie_line('"a string"') is None
	assert parse_cowrie_line("not json at all") is None


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