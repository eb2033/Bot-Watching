from __future__ import annotations

import math
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from dashboard.services.queries import (
	count_alerts,
	get_activity_timeseries,
	get_alert_filter_options,
	get_alerts,
	get_alerts_severity_timeseries,
)
from engine.db.session import get_db_session

api_bp = Blueprint("api", __name__)


@api_bp.route("/alerts")
def alerts():
	severity = request.args.get("severity") or None
	rule_name = request.args.get("rule_name") or None
	page = max(request.args.get("page", default=1, type=int), 1)
	page_size = request.args.get("page_size", default=15, type=int)
	offset = (page - 1) * page_size

	with get_db_session() as db:
		rows = get_alerts(db, severity=severity, rule_name=rule_name, limit=page_size, offset=offset)
		total = count_alerts(db, severity=severity, rule_name=rule_name)

	return jsonify(
		{
			"rows": rows,
			"total": total,
			"page": page,
			"page_size": page_size,
			"total_pages": max(math.ceil(total / page_size), 1),
		}
	)


@api_bp.route("/alerts/filters")
def alert_filters():
	with get_db_session() as db:
		options = get_alert_filter_options(db)

	return jsonify(options)


@api_bp.route("/activity")
def activity():
	hours = request.args.get("hours", default=24, type=int)

	with get_db_session() as db:
		rows = get_alerts_severity_timeseries(db, hours=hours)

	return jsonify(rows)


@api_bp.route("/activity/volume")
def activity_volume():
	now = datetime.now(timezone.utc)
	year = request.args.get("year", default=now.year, type=int)
	month = request.args.get("month", default=now.month, type=int)

	if month < 1 or month > 12:
		return jsonify({"error": "month must be between 1 and 12"}), 400
	if (year, month) > (now.year, now.month):
		return jsonify({"error": "cannot request a future month"}), 400

	start = datetime(year, month, 1, tzinfo=timezone.utc)

	with get_db_session() as db:
		rows = get_activity_timeseries(db, start=start, end=now)

	return jsonify(rows)
