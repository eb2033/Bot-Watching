from engine.config import USERNAMES_PATH, PASSWORDS_PATH
from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, Alert
from pathlib import Path
from collections import defaultdict

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
        
class BruteForceDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self._fail_counts: dict[str,int] = defaultdict(int)

    def check(self,event:AuthAttemptEvent) -> Alert | None:
        if event.success:
            self._fail_counts[event.src_ip] = 0  # Reset on success
            return None
        else:
            self._fail_counts[event.src_ip] += 1
            if self._fail_counts[event.src_ip] % self.threshold == 0:
                return Alert(
                    session_id=event.session_id,
                    eventid=event.eventid,
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                    raw=event.raw,
                    rule_name="Brute Force Attack",
                    severity="High",
                    details=f"Detected {self._fail_counts[event.src_ip]} failed login attempts from {event.src_ip}"
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

