from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import Select, func, select

from engine.db.models import Alert, AuthAttempt, Command, Download, Session as SessionRow

SEVERITY_ORDER = ["High", "Medium", "Low"]
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}


def _apply_alert_filters(stmt: Select, severity: str | None, rule_name: str | None) -> Select:
	if severity:
		stmt = stmt.where(Alert.severity == severity)
	if rule_name:
		stmt = stmt.where(Alert.rule_name == rule_name)
	return stmt


def get_alerts(
	db,
	severity: str | None = None,
	rule_name: str | None = None,
	limit: int = 15,
	offset: int = 0,
) -> list[dict[str, Any]]:
	stmt = (
		select(
			Alert.id,
			Alert.timestamp,
			Alert.rule_name,
			Alert.severity,
			Alert.details,
			SessionRow.src_ip,
		)
		.join(SessionRow, Alert.session_id == SessionRow.session_id)
		.order_by(Alert.timestamp.desc())
		.limit(limit)
		.offset(offset)
	)
	stmt = _apply_alert_filters(stmt, severity, rule_name)

	rows = db.execute(stmt).all()

	return [
		{
			"id": row.id,
			"timestamp": row.timestamp.isoformat(),
			"src_ip": row.src_ip,
			"rule_name": row.rule_name,
			"severity": row.severity,
			"details": row.details,
		}
		for row in rows
	]


def count_alerts(db, severity: str | None = None, rule_name: str | None = None) -> int:
	stmt = _apply_alert_filters(select(func.count(Alert.id)), severity, rule_name)
	return db.execute(stmt).scalar_one()


def get_alert_filter_options(db) -> dict[str, list[str]]:
	severities = [row[0] for row in db.execute(select(Alert.severity).distinct()).all()]
	rule_names = sorted(row[0] for row in db.execute(select(Alert.rule_name).distinct()).all())

	severities.sort(key=lambda value: (_SEVERITY_RANK.get(value, len(SEVERITY_ORDER)), value))

	return {"severities": severities, "rule_names": rule_names}


def get_alerts_severity_timeseries(db, hours: int = 24) -> list[dict[str, Any]]:
	now = datetime.now(timezone.utc)
	since = now - timedelta(hours=hours)

	bucket = func.date_trunc("hour", Alert.timestamp).label("bucket")
	stmt = (
		select(bucket, Alert.severity, func.count().label("count"))
		.where(Alert.timestamp >= since)
		.group_by(bucket, Alert.severity)
	)
	counts = {(row.bucket, row.severity): row.count for row in db.execute(stmt).all()}

	start = since.replace(minute=0, second=0, microsecond=0)
	end = now.replace(minute=0, second=0, microsecond=0)

	buckets: list[datetime] = []
	cursor = start
	while cursor <= end:
		buckets.append(cursor)
		cursor += timedelta(hours=1)

	rows = []
	for current in buckets:
		row = {"timestamp_bucket": current.isoformat()}
		for severity in SEVERITY_ORDER:
			row[severity] = counts.get((current, severity), 0)
		rows.append(row)
	return rows


def get_activity_timeseries(db, start: datetime, end: datetime) -> list[dict[str, Any]]:
	counts: dict[datetime, int] = defaultdict(int)
	for model in (AuthAttempt, Command, Download):
		bucket = func.date_trunc("hour", model.timestamp).label("bucket")
		stmt = (
			select(bucket, func.count().label("count"))
			.where(model.timestamp >= start, model.timestamp <= end)
			.group_by(bucket)
		)
		for row in db.execute(stmt).all():
			counts[row.bucket] += row.count

	bucket_start = start.replace(minute=0, second=0, microsecond=0)
	bucket_end = end.replace(minute=0, second=0, microsecond=0)

	rows = []
	cursor = bucket_start
	while cursor <= bucket_end:
		rows.append({"timestamp_bucket": cursor.isoformat(), "count": counts.get(cursor, 0)})
		cursor += timedelta(hours=1)
	return rows
