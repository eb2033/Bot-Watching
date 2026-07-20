import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT_STR = str(PROJECT_ROOT)
if PROJECT_ROOT_STR not in sys.path:
    sys.path.insert(0, PROJECT_ROOT_STR)

from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, SessionConnectEvent


def _parse_connect(event: dict) -> SessionConnectEvent:
    return SessionConnectEvent(
        session_id=event["session"],
        eventid=event["eventid"],
        timestamp=event["timestamp"],
        src_ip=event["src_ip"],
        src_port=event["src_port"],
        dst_port=event["dst_port"],
        protocol=event["protocol"],
        raw=event
    )

def _parse_auth(event: dict) -> AuthAttemptEvent:
    return AuthAttemptEvent(
        session_id=event["session"],
        eventid=event["eventid"],
        timestamp=event["timestamp"],
        src_ip=event["src_ip"],
        username=event["username"],
        password=event["password"],
        success=(event["eventid"] == "cowrie.login.success"),
        raw=event
    )

def _parse_command(event: dict) -> CommandEvent:
    return CommandEvent(
        session_id=event["session"],
        eventid=event["eventid"],
        timestamp=event["timestamp"],
        src_ip=event["src_ip"],
        input=event["input"],
        raw=event
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
        raw=event
    )

def skip_event(event: dict) -> None:
    print(f"Skipped event: {event['eventid']}")

_EVENT_MAP = {
    "cowrie.session.connect": _parse_connect,
    "cowrie.login.success": _parse_auth,
    "cowrie.login.failed": _parse_auth,
    "cowrie.command.input": _parse_command,
    "cowrie.session.file_download": _parse_download
}

def parse_line(event: dict):
    handler = _EVENT_MAP.get(event["eventid"])
    if handler is None:
        skip_event(event)
        return None
    return handler(event)


def main() -> None:
    num_lines = 8
    print(f"Reading last {num_lines} lines from sampleLog.json")

    sample_log_path = PROJECT_ROOT / "engine" / "sampleLog.json"
    with open(sample_log_path, "r") as f:
        data = json.load(f)

    parsed_events = []
    for line in data[-num_lines:]:
        parsed_event = parse_line(line)
        if parsed_event is not None:
            parsed_events.append(parsed_event)

    print(f"Parsed {len(parsed_events)} events:")
    for event in parsed_events:
        print(event.json())


if __name__ == "__main__":
    main()
