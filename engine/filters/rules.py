from engine.config import USERNAMES_PATH, PASSWORDS_PATH
from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, Alert
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta

def _load_wordlist(file_path: Path) -> set[str]:
    if not file_path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {file_path}")
    with open(file_path, 'r') as f:
        return set(line.strip() for line in f if line.strip())

_SUSPICIOUS_EXTENSIONS = (".exe",".sh",".php",".zip",".tar.gz",".bin")

def check_file_download(event:DownloadEvent) -> Alert | None:
    if event.filename.endswith(_SUSPICIOUS_EXTENSIONS):
        return Alert(
            session_id=event.session_id,
            eventid=event.eventid,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
            raw=event.raw,
            rule_name="Suspicious Download",
            severity="High",
            details=f"Downloaded file: {event.filename} from {event.url} , sha256: {event.sha256}"
        )

_BAD_USERNAMES = _load_wordlist(USERNAMES_PATH)
_BAD_PASSWORDS = _load_wordlist(PASSWORDS_PATH)
     
def check_bad_creds(event:AuthAttemptEvent) -> Alert | None:
    if event.username in _BAD_USERNAMES or event.password in _BAD_PASSWORDS:
        return Alert(
            session_id=event.session_id,
            eventid=event.eventid,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
            raw=event.raw,
            rule_name="Bad Credentials",
            severity="Low",
            details=f"Attempted login with bad credentials: username={event.username}, password={event.password}"
        )
        
BRUTE_FORCE_WINDOW_SECONDS = 600


class BruteForceDetector:
    """Flags `threshold` failed logins from one source IP within `window_seconds`.

    Only the last `threshold` failure times per IP are retained - that's all
    that's needed to decide whether the threshold was reached inside the window.

    Times come from the events themselves, never the wall clock, so replaying
    an older log (which the listener does after a restart or a log rotation)
    windows against the timestamps in that log rather than "now".
    """

    def __init__(self, threshold: int = 5, window_seconds: float = BRUTE_FORCE_WINDOW_SECONDS):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._failures: dict[str, deque[datetime]] = defaultdict(lambda: deque(maxlen=threshold))
        self._last_sweep: datetime | None = None

    def _sweep_expired(self, now: datetime) -> None:
        """Drop IPs whose most recent failure has aged out of the window."""
        cutoff = now - self.window
        stale = [src_ip for src_ip, times in self._failures.items() if not times or times[-1] < cutoff]
        for src_ip in stale:
            del self._failures[src_ip]
        self._last_sweep = now

    def check(self, event: AuthAttemptEvent) -> Alert | None:
        now = event.timestamp

        # Amortised cleanup: at most one full pass per window, so the cost is
        # negligible next to the per-event work.
        if self._last_sweep is None:
            self._last_sweep = now
        elif now - self._last_sweep >= self.window:
            self._sweep_expired(now)

        if event.success:
            self._failures.pop(event.src_ip, None)  # Reset on success
            return None

        failures = self._failures[event.src_ip]
        failures.append(now)

        if len(failures) < self.threshold or now - failures[0] > self.window:
            return None

        # Consume the run so a sustained attack alerts once per `threshold`
        # failures, rather than on every failure once the threshold is passed.
        del self._failures[event.src_ip]

        return Alert(
            session_id=event.session_id,
            eventid=event.eventid,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
            raw=event.raw,
            rule_name="Brute Force Attack",
            severity="High",
            details=(
                f"Detected {self.threshold} failed login attempts from {event.src_ip} "
                f"within {int(self.window.total_seconds())}s"
            )
        )
        
_SUSPICIOUS_KEYWORDS = ["rm -rf", "wget", "curl", "nc", "netcat", "python -c", "perl -e","busybox","/bin/sh","/bin/bash","chmod","/etc/passwd"]

def check_command_input(event: CommandEvent) -> Alert | None:
    command = event.input.lower()
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword.lower() in command:
            return Alert(
                session_id=event.session_id,
                eventid=event.eventid,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
                raw=event.raw,
                rule_name="Suspicious Command",
                severity="Medium",
                details=f"Matched suspicious keyword '{keyword}' in command: {event.input}"
            )

