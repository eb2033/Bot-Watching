from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT_STR = str(PROJECT_ROOT)

if PROJECT_ROOT_STR not in sys.path:
	sys.path.insert(0, PROJECT_ROOT_STR)

from engine.db.crud import (
	insert_alert,
	insert_auth_attempt,
	insert_command,
	insert_download,
	insert_session,
	enrich_ip,
)
from engine.db.migrate import upgrade_to_head
from engine.db.models import Session as SessionRow, IPEnrichment as IPEnrichmentRow
from engine.db.session import get_db_session, get_engine
from engine.enrichment.enrichment import lookup_ip
from engine.filters.rules import (
	BruteForceDetector,
	check_bad_creds,
	check_command_input,
	check_file_download,
)
from engine.healthcheck import HEARTBEAT_PATH
from engine.listener import CowrieLogListener, ParsedEvent, parse_cowrie_line
from engine.parser.schemas import (
	Alert,
	AuthAttemptEvent,
	CommandEvent,
	DownloadEvent,
	SessionConnectEvent,
	IPEnrichment as IPEnrichmentEvent,
)

logger = logging.getLogger(__name__)


def _build_placeholder_session(event: ParsedEvent):
	return SessionRow(
		session_id=event.session_id,
		src_ip=event.src_ip,
		start_time=event.timestamp,
		protocol=str(event.raw.get("protocol", "ssh")),
	)


def _store_ip_enrichment(db, src_ip: str) -> None:
	if db.get(IPEnrichmentRow, src_ip) is not None:
		return

	lookup_result = lookup_ip(src_ip)
	if lookup_result is None:
		return

	enrich_ip(
		db,
		IPEnrichmentEvent(
			src_ip=src_ip,
			country=lookup_result["country"],
			city=lookup_result["city"],
			asn=lookup_result["asn"],
			org=lookup_result["org"],
			latitude=lookup_result["latitude"],
			longitude=lookup_result["longitude"],
			enriched_at=datetime.now(timezone.utc),
		),
	)


@dataclass(slots=True)
class EngineProcessor:
	brute_force_detector: BruteForceDetector = field(default_factory=BruteForceDetector)
	known_sessions: set[str] = field(default_factory=set)

	def _ensure_session(self, db, event: ParsedEvent) -> None:
		if event.session_id in self.known_sessions:
			return

		if db.get(SessionRow, event.session_id) is not None:
			self.known_sessions.add(event.session_id)
			return

		if isinstance(event, SessionConnectEvent):
			insert_session(db, event)
			self.known_sessions.add(event.session_id)
			return

		db.add(_build_placeholder_session(event))
		self.known_sessions.add(event.session_id)

	def _store_alert(self, db, alert: Alert | None) -> None:
		if alert is None:
			return
		insert_alert(db, alert, rule_name=alert.rule_name, severity=alert.severity, details=alert.details)

	def _process_event(self, db, event: ParsedEvent) -> None:
		self._ensure_session(db, event)

		if isinstance(event, SessionConnectEvent):
			_store_ip_enrichment(db, event.src_ip)
			self.known_sessions.add(event.session_id)
			return

		if isinstance(event, AuthAttemptEvent):
			insert_auth_attempt(db, event)
			self._store_alert(db, check_bad_creds(event))
			self._store_alert(db, self.brute_force_detector.check(event))
			return

		if isinstance(event, CommandEvent):
			insert_command(db, event)
			self._store_alert(db, check_command_input(event))
			return

		if isinstance(event, DownloadEvent):
			insert_download(db, event)
			self._store_alert(db, check_file_download(event))

	def process_event(self, db, event: ParsedEvent) -> None:
		try:
			with db.begin_nested():
				self._process_event(db, event)
		except IntegrityError:
			return


@dataclass(slots=True)
class EngineRuntime:
	listener: CowrieLogListener
	processor: EngineProcessor = field(default_factory=EngineProcessor)
	poll_interval_seconds: float = 2.0
	max_backoff_seconds: float = 60.0
	heartbeat_path: Path | None = None

	def process_next_batch(self) -> int:
		raw_lines = self.listener.read_batch()
		if not raw_lines:
			# Nothing to write, but still prove the DB is reachable so an idle
			# engine with a dead database doesn't keep reporting healthy.
			with get_engine().connect() as connection:
				connection.execute(text("SELECT 1"))
			return 0

		with get_db_session() as db:
			for raw_line in raw_lines:
				event = parse_cowrie_line(raw_line)
				if event is None:
					continue
				self.processor.process_event(db, event)

		self.listener.discard_processed(len(raw_lines))
		return len(raw_lines)

	def _record_heartbeat(self) -> None:
		if self.heartbeat_path is not None:
			self.heartbeat_path.touch()

	def run_forever(self) -> None:
		consecutive_failures = 0

		while True:
			try:
				processed_count = self.process_next_batch()
			except Exception:
				# Transient infrastructure faults (DB failover, connection
				# drop, network blip)
				consecutive_failures += 1
				backoff_seconds = min(
					self.poll_interval_seconds * (2 ** (consecutive_failures - 1)),
					self.max_backoff_seconds,
				)
				logger.exception(
					"Batch failed (consecutive failures: %d), retrying in %.1fs",
					consecutive_failures,
					backoff_seconds,
				)
				time.sleep(backoff_seconds)
				continue

			if consecutive_failures:
				logger.info("Recovered after %d consecutive failure(s)", consecutive_failures)
			consecutive_failures = 0
			self._record_heartbeat()

			if processed_count == 0:
				time.sleep(self.poll_interval_seconds)


def _get_log_path() -> Path:
	return Path(os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json"))


def _get_batch_size() -> int:
	return int(os.getenv("LISTENER_BATCH_SIZE", "5"))


def _get_poll_interval() -> float:
	return float(os.getenv("LISTENER_POLL_INTERVAL_SECONDS", "2"))


def main() -> None:
	logging.basicConfig(
		level=os.getenv("LOG_LEVEL", "INFO").upper(),
		format="%(asctime)s %(levelname)s %(name)s: %(message)s",
	)

	upgrade_to_head(get_engine())
	runtime = EngineRuntime(
		listener=CowrieLogListener(log_path=_get_log_path(), batch_size=_get_batch_size()),
		poll_interval_seconds=_get_poll_interval(),
		heartbeat_path=HEARTBEAT_PATH,
	)
	logger.info("Engine started, polling %s", _get_log_path())
	runtime.run_forever()


if __name__ == "__main__":
	main()
