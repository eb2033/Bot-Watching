from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, SessionConnectEvent


ParsedEvent = AuthAttemptEvent | CommandEvent | DownloadEvent | SessionConnectEvent


def _parse_connect(event: dict) -> SessionConnectEvent:
	return SessionConnectEvent(
		session_id=event["session"],
		eventid=event["eventid"],
		timestamp=event["timestamp"],
		src_ip=event["src_ip"],
		src_port=event["src_port"],
		dst_port=event["dst_port"],
		protocol=event["protocol"],
		raw=event,
	)


def _parse_auth(event: dict) -> AuthAttemptEvent:
	return AuthAttemptEvent(
		session_id=event["session"],
		eventid=event["eventid"],
		timestamp=event["timestamp"],
		src_ip=event["src_ip"],
		username=event["username"],
		password=event["password"],
		success=event["eventid"] == "cowrie.login.success",
		raw=event,
	)


def _parse_command(event: dict) -> CommandEvent:
	return CommandEvent(
		session_id=event["session"],
		eventid=event["eventid"],
		timestamp=event["timestamp"],
		src_ip=event["src_ip"],
		input=event["input"],
		raw=event,
	)


def _parse_download(event: dict) -> DownloadEvent:
	return DownloadEvent(
		session_id=event["session"],
		eventid=event["eventid"],
		timestamp=event["timestamp"],
		src_ip=event["src_ip"],
		url=event.get("url", "N/A"),
		filename=event.get("filename", "N/A"),
		file_path=event.get("file_path", "N/A"),
		sha256=event.get("sha256", "N/A"),
		raw=event,
	)


EVENT_BUILDERS: dict[str, Callable[[dict], ParsedEvent]] = {
	"cowrie.session.connect": _parse_connect,
	"cowrie.login.success": _parse_auth,
	"cowrie.login.failed": _parse_auth,
	"cowrie.command.input": _parse_command,
	"cowrie.session.file_download": _parse_download,
}


def parse_cowrie_line(line: str) -> ParsedEvent | None:
	try:
		payload = json.loads(line)
	except json.JSONDecodeError:
		return None

	builder = EVENT_BUILDERS.get(payload.get("eventid", ""))
	if builder is None:
		return None
	return builder(payload)


@dataclass(slots=True)
class CowrieLogListener:

	log_path: Path
	batch_size: int = 5
	_offset: int = field(default=0, init=False, repr=False)
	_next_offset: int = field(default=0, init=False, repr=False)

	def read_batch(self) -> list[str]:
		if not self.log_path.exists():
			return []

		lines: list[str] = []
		offset = self._offset
		with self.log_path.open("r", encoding="utf-8") as f:
			f.seek(offset)
			while len(lines) < self.batch_size:
				line = f.readline()
				if not line.endswith("\n"):
					# Incomplete line - the writer hasn't flushed the trailing
					# newline yet. Stop without consuming it; retry the same
					# offset on the next poll instead of processing a
					# truncated JSON payload.
					break
				offset = f.tell()
				stripped = line.strip()
				if stripped:
					lines.append(stripped)

		self._next_offset = offset
		return lines

	def discard_processed(self, processed_count: int) -> None:
		if processed_count <= 0:
			return
		self._offset = self._next_offset
