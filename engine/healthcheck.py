"""Container healthcheck: `python -m engine.healthcheck` exits 0 when healthy.

The engine loop touches HEARTBEAT_PATH after every successful poll (see
EngineRuntime in engine/main.py). If polling keeps failing (DB down, log
unreadable) the file goes stale and the container is reported unhealthy.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HEARTBEAT_PATH = Path("/tmp/engine-heartbeat")
# Comfortably above the worst-case retry backoff (60s) plus one poll interval.
MAX_HEARTBEAT_AGE_SECONDS = 120.0


def is_healthy(heartbeat_path: Path, max_age_seconds: float) -> bool:
	try:
		last_beat = heartbeat_path.stat().st_mtime
	except FileNotFoundError:
		return False
	return time.time() - last_beat <= max_age_seconds


def main() -> int:
	return 0 if is_healthy(HEARTBEAT_PATH, MAX_HEARTBEAT_AGE_SECONDS) else 1


if __name__ == "__main__":
	sys.exit(main())
