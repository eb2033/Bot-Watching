from __future__ import annotations

import json
from dataclasses import dataclass
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

	def read_batch(self) -> list[str]:
		if not self.log_path.exists():
			return []

		lines = [line for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
		return lines[: self.batch_size]

	def discard_processed(self, processed_count: int) -> None:
		if processed_count <= 0 or not self.log_path.exists():
			return

		lines = [line for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
		remaining_lines = lines[processed_count:]
		content = "\n".join(remaining_lines)
		if content:
			content += "\n"
		self.log_path.write_text(content, encoding="utf-8")
