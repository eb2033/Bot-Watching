from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session as OrmSession

from db.models import Alert, AuthAttempt, Base, Command, Download, Session


def test_metadata_defines_expected_tables():
    assert set(Base.metadata.tables) == {
        "sessions",
        "auth_attempts",
        "commands",
        "downloads",
        "alerts",
        "ip_enrichment",
    }


def test_sessions_primary_key_and_indexes():
    sessions = Session.__table__

    assert [column.name for column in sessions.primary_key.columns] == ["session_id"]
    assert {index.name for index in sessions.indexes} == {"ix_sessions_src_ip", "ix_sessions_start_time"}


def test_child_tables_reference_sessions_and_dedup_columns():
    child_tables = {
        AuthAttempt.__table__: ("uq_auth_attempt_dedup", {"session_id", "timestamp", "username", "password"}),
        Command.__table__: ("uq_command_dedup", {"session_id", "timestamp", "input"}),
        Download.__table__: ("uq_download_dedup", {"session_id", "timestamp", "url", "sha256"}),
        Alert.__table__: ("uq_alert_dedup", {"session_id", "timestamp", "rule_name"}),
    }

    for table, (constraint_name, constraint_columns) in child_tables.items():
        assert [column.name for column in table.c if column.primary_key][0] == "id"
        assert {fk.column.table.name for fk in table.c.session_id.foreign_keys} == {"sessions"}
        assert constraint_name in {constraint.name for constraint in table.constraints if constraint.name}
        assert any(
            getattr(constraint, "columns", None) is not None
            and {column.name for column in constraint.columns} == constraint_columns
            for constraint in table.constraints
        )


def test_metadata_creates_cleanly_in_sqlite():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    inspector = inspect(engine)
    assert inspector.get_table_names() == ["alerts", "auth_attempts", "commands", "downloads", "ip_enrichment", "sessions"]


def test_string_fields_are_sanitized_before_persist():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    clean_session_id = "sess-01"
    dirty_protocol = "ssh\x1b]0;bad-title\x07"
    dirty_command_input = ("\x1b[32mRUN\x1b[0m" + "\udcff" + "A" * 5000 + "\x00\t\n")  # over Command.input max length
    dirty_rule_name = "Rule\x1b[31mName"
    dirty_severity = "High\x00"

    with OrmSession(engine) as db:
        db.add(
            Session(
                session_id=clean_session_id,
                src_ip="10.10.10.20",
                start_time=datetime.now(timezone.utc),
                protocol=dirty_protocol,
            )
        )
        db.flush()

        db.add(
            Command(
                session_id=clean_session_id,
                input=dirty_command_input,
                timestamp=datetime.now(timezone.utc),
            )
        )
        db.add(
            Alert(
                session_id=clean_session_id,
                rule_name=dirty_rule_name,
                severity=dirty_severity,
                details="Matched suspicious keyword 'passwd' in command: cat /etc/passwd",
                timestamp=datetime.now(timezone.utc),
            )
        )
        db.commit()

        saved_session = db.get(Session, clean_session_id)
        assert saved_session is not None
        assert saved_session.protocol == "ssh"

        saved_command = db.query(Command).one()
        assert len(saved_command.input) == 4096
        assert "\x1b" not in saved_command.input
        assert "\x00" not in saved_command.input
        assert "\t" not in saved_command.input
        assert "\n" not in saved_command.input
        assert "\udcff" not in saved_command.input

        saved_alert = db.query(Alert).one()
        assert saved_alert.rule_name == dirty_rule_name
        assert saved_alert.severity == dirty_severity
