from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, SessionConnectEvent


logger = logging.getLogger(__name__)

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

	if not isinstance(payload, dict):
		return None

	builder = EVENT_BUILDERS.get(payload.get("eventid", ""))
	if builder is None:
		return None

	try:
		return builder(payload)
	except (KeyError, ValidationError) as exc:
		# An event missing fields the builder requires. Skip it rather than
		# propagate: run_forever retries a failed batch, so a single bad line
		# would otherwise stall ingestion permanently instead of crashing
		# loudly the way it used to.
		logger.warning("Skipping unparseable %s event: %s", payload.get("eventid"), exc)
		return None


@dataclass(slots=True)
class CowrieLogListener:

	log_path: Path
	batch_size: int = 5
	_offset: int = field(default=0, init=False, repr=False)
	_next_offset: int = field(default=0, init=False, repr=False)
	_inode: int | None = field(default=None, init=False, repr=False)

	def _reset_if_rotated(self, stat_result: os.stat_result) -> None:
		"""Restart from the top of the file when the log has been rotated or
		truncated underneath us.
		"""
		rotated = self._inode is not None and stat_result.st_ino != self._inode
		truncated = stat_result.st_size < self._offset

		if rotated or truncated:
			logger.info(
				"%s was %s (size=%d, offset=%d); rewinding to start of file",
				self.log_path,
				"rotated" if rotated else "truncated",
				stat_result.st_size,
				self._offset,
			)
			self._offset = 0
			self._next_offset = 0

		self._inode = stat_result.st_ino

	def read_batch(self) -> list[str]:
		try:
			stat_result = self.log_path.stat()
		except FileNotFoundError:
			# Normal before Cowrie has written its first event.
			return []
		except OSError as exc:
			# Anything else (permissions, bad mount) would otherwise stall
			# ingestion silently, so make it visible on every poll.
			logger.warning("Cannot stat %s: %s", self.log_path, exc)
			return []

		self._reset_if_rotated(stat_result)

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
