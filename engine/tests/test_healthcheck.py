from __future__ import annotations

import os
import time

import pytest

import engine.main as engine_main
from engine.healthcheck import is_healthy
from engine.listener import CowrieLogListener
from engine.main import EngineRuntime


class _StopLoop(Exception):
	pass


def _stop_loop(_seconds: float) -> None:
	raise _StopLoop


def test_missing_heartbeat_is_unhealthy(tmp_path):
	assert is_healthy(tmp_path / "heartbeat", max_age_seconds=120) is False


def test_fresh_heartbeat_is_healthy(tmp_path):
	heartbeat_path = tmp_path / "heartbeat"
	heartbeat_path.touch()

	assert is_healthy(heartbeat_path, max_age_seconds=120) is True


def test_stale_heartbeat_is_unhealthy(tmp_path):
	heartbeat_path = tmp_path / "heartbeat"
	heartbeat_path.touch()
	stale_time = time.time() - 300
	os.utime(heartbeat_path, (stale_time, stale_time))

	assert is_healthy(heartbeat_path, max_age_seconds=120) is False


def test_runtime_records_heartbeat_after_successful_poll(tmp_path, monkeypatch):
	monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'engine.sqlite3'}")
	heartbeat_path = tmp_path / "heartbeat"
	log_path = tmp_path / "cowrie.json"
	log_path.touch()
	runtime = EngineRuntime(
		listener=CowrieLogListener(log_path=log_path, batch_size=5),
		heartbeat_path=heartbeat_path,
	)
	monkeypatch.setattr(engine_main.time, "sleep", _stop_loop)

	with pytest.raises(_StopLoop):
		runtime.run_forever()

	assert is_healthy(heartbeat_path, max_age_seconds=120) is True


def test_idle_runtime_skips_heartbeat_when_database_unreachable(tmp_path, monkeypatch):
	# No new log lines means no DB writes - the idle poll must still prove
	# the database is reachable, or an idle engine reports healthy forever.
	monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path / 'missing-dir' / 'engine.sqlite3'}")
	heartbeat_path = tmp_path / "heartbeat"
	log_path = tmp_path / "cowrie.json"
	log_path.touch()
	runtime = EngineRuntime(
		listener=CowrieLogListener(log_path=log_path, batch_size=5),
		heartbeat_path=heartbeat_path,
	)
	monkeypatch.setattr(engine_main.time, "sleep", _stop_loop)

	with pytest.raises(_StopLoop):
		runtime.run_forever()

	assert heartbeat_path.exists() is False


class _FailingListener:
	def read_batch(self) -> list[str]:
		raise RuntimeError("log source unavailable")


def test_runtime_skips_heartbeat_when_batch_fails(tmp_path, monkeypatch):
	heartbeat_path = tmp_path / "heartbeat"
	runtime = EngineRuntime(listener=_FailingListener(), heartbeat_path=heartbeat_path)
	monkeypatch.setattr(engine_main.time, "sleep", _stop_loop)

	with pytest.raises(_StopLoop):
		runtime.run_forever()

	assert heartbeat_path.exists() is False
