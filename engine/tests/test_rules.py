
from datetime import datetime
from parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent
from filters.rules import check_file_download, check_bad_creds, check_command_input, BruteForceDetector


def _make_auth_event(username="user", password="pass", success=False, src_ip="1.2.3.4"):
    return AuthAttemptEvent(
        session_id="test-session",
        eventid="cowrie.login.failed",
        timestamp=datetime.now(),
        src_ip=src_ip,
        raw={},
        username=username,
        password=password,
        success=success,
    )


def _make_command_event(command="ls -la", src_ip="1.2.3.4"):
    return CommandEvent(
        session_id="test-session",
        eventid="cowrie.command.input",
        timestamp=datetime.now(),
        src_ip=src_ip,
        raw={},
        input=command,
    )


def _make_download_event(filename="payload.exe", url="http://1.2.3.4/payload.exe", src_ip="1.2.3.4"):
    return DownloadEvent(
        session_id="test-session",
        eventid="cowrie.session.file_download",
        timestamp=datetime.now(),
        src_ip=src_ip,
        raw={},
        url=url,
        filename=filename,
        file_path="/tmp/" + filename,
        sha256="a" * 64,
    )


def test_bad_creds_flags_root():
    event = _make_auth_event(username="root")
    alert = check_bad_creds(event)
    assert alert is not None
    assert alert.rule_name == "Bad Credentials"


def test_bad_creds_ignores_clean_login():
    event = _make_auth_event(username="realuser", password="Xk92!plq")
    alert = check_bad_creds(event)
    assert alert is None


def test_brute_force_fires_at_threshold():
    detector = BruteForceDetector(threshold=3)
    for _ in range(2):
        assert detector.check(_make_auth_event(src_ip="9.9.9.9")) is None
    alert = detector.check(_make_auth_event(src_ip="9.9.9.9"))
    assert alert is not None


def test_brute_force_resets_on_success():
    detector = BruteForceDetector(threshold=3)
    detector.check(_make_auth_event(src_ip="9.9.9.9"))
    detector.check(_make_auth_event(src_ip="9.9.9.9", success=True))
    # only 1 failure recorded again after the reset — shouldn't fire yet
    alert = detector.check(_make_auth_event(src_ip="9.9.9.9"))
    assert alert is None


def test_command_input_flags_suspicious_keyword():
    event = _make_command_event(command="cat /etc/passwd")
    alert = check_command_input(event)
    assert alert is not None
    assert alert.rule_name == "Suspicious Command"
    assert alert.severity == "Medium"


def test_command_input_ignores_clean_command():
    event = _make_command_event(command="echo hello world")
    alert = check_command_input(event)
    assert alert is None


def test_file_download_flags_suspicious_extension():
    event = _make_download_event(filename="malware.exe")
    alert = check_file_download(event)
    assert alert is not None
    assert alert.rule_name == "Suspicious Download"
    assert alert.severity == "High"


def test_file_download_ignores_clean_extension():
    event = _make_download_event(filename="notes.txt")
    alert = check_file_download(event)
    assert alert is None