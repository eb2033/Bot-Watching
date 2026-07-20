from engine.db.models import AuthAttempt, Session as SessionRow, Command as CommandRow, Download as DownloadRow, Alert as AlertRow, IPEnrichment
from engine.parser.schemas import AuthAttemptEvent, CommandEvent, DownloadEvent, SessionConnectEvent, Alert, IPEnrichment as IPEnrichmentEvent


def insert_session(db, event: SessionConnectEvent) -> SessionRow:
    row = SessionRow(
        session_id=event.session_id,
        src_ip=event.src_ip,
        start_time=event.timestamp,
        protocol=event.protocol,
    )
    db.add(row)
    return row


def enrich_ip(db, event: IPEnrichmentEvent) -> None:
    enrichment_row = IPEnrichment(
        src_ip=event.src_ip,
        country=event.country,
        city=event.city,
        asn=event.asn,
        org=event.org,
        enriched_at=event.enriched_at,
    )
    db.add(enrichment_row)


def insert_auth_attempt(db, event: AuthAttemptEvent) -> AuthAttempt:
    row = AuthAttempt(
        session_id=event.session_id,
        username=event.username,
        password=event.password,
        success=event.success,
        timestamp=event.timestamp,
    )
    db.add(row)
    return row


def insert_command(db, event: CommandEvent) -> CommandRow:
    row = CommandRow(
        session_id=event.session_id,
        input=event.input,
        timestamp=event.timestamp,
    )
    db.add(row)
    return row


def insert_download(db, event: DownloadEvent) -> DownloadRow:
    row = DownloadRow(
        session_id=event.session_id,
        url=event.url,
        filename=event.filename,
        file_path=event.file_path,
        sha256=event.sha256,
        timestamp=event.timestamp,
    )
    db.add(row)
    return row


def insert_alert(db, event: Alert, rule_name: str, severity: str, details: str) -> AlertRow:
    row = AlertRow(
        session_id=event.session_id,
        rule_name=rule_name,
        severity=severity,
        details=details,
        timestamp=event.timestamp,
    )
    db.add(row)
    return row