const SEVERITY_ORDER = ["High", "Medium", "Low"];
const CHART_HISTORY_HOURS = 24 * 365;
const MONTH_NAMES = [
	"January", "February", "March", "April", "May", "June",
	"July", "August", "September", "October", "November", "December",
];

const state = {
	page: 1,
	pageSize: 15,
	totalPages: 1,
};

const volumeState = {
	year: null,
	month: null, // 1-12, UTC
};

const chartRange = {
	start: null,
	end: null,
};

function escapeHtml(value) {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

function cssVar(name) {
	return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function renderActivityChart(rows) {
	const x = rows.map((row) => row.timestamp_bucket);
	chartRange.start = new Date(x[0]);
	chartRange.end = new Date(x[x.length - 1]);

	const colorBySeverity = {
		High: cssVar("--sev-high"),
		Medium: cssVar("--sev-medium"),
		Low: cssVar("--sev-low"),
	};

	const traces = SEVERITY_ORDER.map((severity) => ({
		type: "scatter",
		mode: "lines",
		name: severity,
		x,
		y: rows.map((row) => row[severity]),
		line: { color: colorBySeverity[severity], width: 2 },
		hovertemplate: `${severity}: <b>%{y}</b><extra></extra>`,
	}));

	const now = new Date();
	const startOfToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

	const layout = {
		paper_bgcolor: "transparent",
		plot_bgcolor: "transparent",
		margin: { l: 48, r: 16, t: 36, b: 40 },
		font: { color: cssVar("--text-muted"), family: "system-ui, -apple-system, 'Segoe UI', sans-serif" },
		legend: {
			orientation: "h",
			y: 1.15,
			yanchor: "bottom",
			x: 0,
			xanchor: "left",
			font: { color: cssVar("--text-secondary") },
		},
		xaxis: {
			type: "date",
			range: [startOfToday.toISOString(), now.toISOString()],
			gridcolor: cssVar("--gridline"),
			linecolor: cssVar("--baseline"),
			tickfont: { color: cssVar("--text-muted") },
			rangeslider: {
				visible: true,
				bgcolor: cssVar("--surface-1"),
				bordercolor: cssVar("--border-solid"),
				borderwidth: 1,
				thickness: 0.12,
				range: [chartRange.start.toISOString(), chartRange.end.toISOString()],
			},
		},
		yaxis: {
			title: { text: "Events", font: { color: cssVar("--text-muted") } },
			rangemode: "tozero",
			gridcolor: cssVar("--gridline"),
			linecolor: cssVar("--baseline"),
			tickfont: { color: cssVar("--text-muted") },
		},
		hovermode: "x unified",
	};

	Plotly.newPlot("activity-chart", traces, layout, { displayModeBar: false, responsive: true }).then(
		attachChartWheelPan
	);
}

function attachChartWheelPan() {
	const chartDiv = document.getElementById("activity-chart");
	if (chartDiv.dataset.wheelBound) return;
	chartDiv.dataset.wheelBound = "true";

	// The rangeslider sits at the bottom of the same SVG; scrolling while over
	// it zooms the selection instead of panning the main plot. Cache its top
	// edge (everything below it is the rangeslider, nothing else is) and
	// refresh on resize rather than querying the DOM on every wheel tick.
	const getRangesliderTop = () => {
		const el = chartDiv.querySelector(".rangeslider-container");
		return el ? el.getBoundingClientRect().top : Infinity;
	};
	let rangesliderTop = getRangesliderTop();
	window.addEventListener("resize", () => {
		rangesliderTop = getRangesliderTop();
	});

	// Wheel fires many events per scroll gesture (trackpads especially). Each
	// relayout is a real (if now much cheaper) redraw, so coalesce bursts into
	// at most one relayout per animation frame instead of one per tick.
	let pendingDeltaY = 0;
	let pendingIsZoom = false;
	let frameQueued = false;

	chartDiv.addEventListener(
		"wheel",
		(event) => {
			event.preventDefault();
			pendingDeltaY += event.deltaY;
			pendingIsZoom = event.clientY >= rangesliderTop;

			if (frameQueued) return;
			frameQueued = true;

			requestAnimationFrame(() => {
				const currentRange = chartDiv.layout.xaxis.range.map((value) => new Date(value));
				if (pendingIsZoom) {
					zoomChartRange(currentRange[0], currentRange[1], pendingDeltaY);
				} else {
					panChartRange(currentRange[0], currentRange[1], pendingDeltaY);
				}
				pendingDeltaY = 0;
				frameQueued = false;
			});
		},
		{ passive: false }
	);
}

function panChartRange(start, end, deltaY) {
	const span = end.getTime() - start.getTime();
	const direction = deltaY > 0 ? -1 : 1; // scroll down -> earlier history, scroll up -> toward now
	const shift = direction * span * 0.2;

	let newStart = new Date(start.getTime() + shift);
	let newEnd = new Date(end.getTime() + shift);

	if (newStart < chartRange.start) {
		newStart = new Date(chartRange.start);
		newEnd = new Date(newStart.getTime() + span);
	}
	if (newEnd > chartRange.end) {
		newEnd = new Date(chartRange.end);
		newStart = new Date(newEnd.getTime() - span);
	}

	Plotly.relayout("activity-chart", { "xaxis.range": [newStart.toISOString(), newEnd.toISOString()] });
}

function zoomChartRange(start, end, deltaY) {
	const span = end.getTime() - start.getTime();
	const center = start.getTime() + span / 2;
	const zoomFactor = deltaY > 0 ? 1.2 : 1 / 1.2; // scroll down -> zoom out, scroll up -> zoom in

	const fullSpan = chartRange.end.getTime() - chartRange.start.getTime();
	const minSpan = 60 * 60 * 1000; // 1 hour
	const newSpan = Math.min(Math.max(span * zoomFactor, minSpan), fullSpan);

	let newStart = new Date(center - newSpan / 2);
	let newEnd = new Date(center + newSpan / 2);

	if (newStart < chartRange.start) {
		newStart = new Date(chartRange.start);
		newEnd = new Date(newStart.getTime() + newSpan);
	}
	if (newEnd > chartRange.end) {
		newEnd = new Date(chartRange.end);
		newStart = new Date(newEnd.getTime() - newSpan);
	}

	Plotly.relayout("activity-chart", { "xaxis.range": [newStart.toISOString(), newEnd.toISOString()] });
}

function highlightChartTimestamp(isoTimestamp) {
	const chartDiv = document.getElementById("activity-chart");
	if (!chartDiv.layout) return;

	const clicked = new Date(isoTimestamp);
	const currentRange = chartDiv.layout.xaxis.range.map((value) => new Date(value));
	const span = currentRange[1].getTime() - currentRange[0].getTime();

	let newStart = new Date(clicked.getTime() - span / 2);
	let newEnd = new Date(clicked.getTime() + span / 2);

	if (newStart < chartRange.start) {
		newStart = new Date(chartRange.start);
		newEnd = new Date(newStart.getTime() + span);
	}
	if (newEnd > chartRange.end) {
		newEnd = new Date(chartRange.end);
		newStart = new Date(newEnd.getTime() - span);
	}

	Plotly.relayout("activity-chart", {
		"xaxis.range": [newStart.toISOString(), newEnd.toISOString()],
		shapes: [
			{
				type: "line",
				xref: "x",
				yref: "paper",
				x0: isoTimestamp,
				x1: isoTimestamp,
				y0: 0,
				y1: 1,
				line: { color: cssVar("--text-primary"), width: 2, dash: "dot" },
			},
		],
	});
}

async function loadActivity() {
	const response = await fetch(`/api/activity?hours=${CHART_HISTORY_HOURS}`);
	const rows = await response.json();
	renderActivityChart(rows);
}

function renderVolumeChart(rows) {
	const x = rows.map((row) => row.timestamp_bucket);
	const y = rows.map((row) => row.count);

	const trace = {
		type: "scatter",
		mode: "lines",
		name: "Events",
		x,
		y,
		line: { color: cssVar("--series-1"), width: 2 },
		hovertemplate: "Events: <b>%{y}</b><extra></extra>",
	};

	const layout = {
		paper_bgcolor: "transparent",
		plot_bgcolor: "transparent",
		margin: { l: 48, r: 16, t: 16, b: 40 },
		font: { color: cssVar("--text-muted"), family: "system-ui, -apple-system, 'Segoe UI', sans-serif" },
		xaxis: {
			type: "date",
			gridcolor: cssVar("--gridline"),
			linecolor: cssVar("--baseline"),
			tickfont: { color: cssVar("--text-muted") },
		},
		yaxis: {
			title: { text: "Events", font: { color: cssVar("--text-muted") } },
			rangemode: "tozero",
			gridcolor: cssVar("--gridline"),
			linecolor: cssVar("--baseline"),
			tickfont: { color: cssVar("--text-muted") },
		},
		hovermode: "x unified",
	};

	Plotly.newPlot("volume-chart", [trace], layout, { displayModeBar: false, responsive: true });
}

function isCurrentVolumeMonth() {
	const now = new Date();
	return volumeState.year === now.getUTCFullYear() && volumeState.month === now.getUTCMonth() + 1;
}

function updateVolumeNavControls() {
	document.getElementById("volume-month-label").textContent = `${MONTH_NAMES[volumeState.month - 1]} ${volumeState.year}`;
	document.getElementById("volume-next").disabled = isCurrentVolumeMonth();
}

async function loadVolume() {
	const params = new URLSearchParams({ year: volumeState.year, month: volumeState.month });
	const response = await fetch(`/api/activity/volume?${params.toString()}`);
	const rows = await response.json();
	renderVolumeChart(rows);
	updateVolumeNavControls();
}

function changeVolumeMonth(delta) {
	let { year, month } = volumeState;
	month += delta;
	if (month < 1) {
		month = 12;
		year -= 1;
	} else if (month > 12) {
		month = 1;
		year += 1;
	}

	const now = new Date();
	if (year > now.getUTCFullYear() || (year === now.getUTCFullYear() && month > now.getUTCMonth() + 1)) {
		return; // no future months
	}

	volumeState.year = year;
	volumeState.month = month;
	loadVolume();
}

function renderAlertsTable(rows) {
	const list = document.getElementById("alerts-list");

	if (rows.length === 0) {
		list.innerHTML = '<li class="empty-row">No alerts match this filter.</li>';
		return;
	}

	list.innerHTML = rows
		.map((row) => {
			const severityKey = row.severity.toLowerCase();
			const timestamp = new Date(row.timestamp).toLocaleString();
			return `<li class="alert-row">
				<div class="alert-row-top">
					<span class="severity-badge" data-severity="${escapeHtml(severityKey)}">${escapeHtml(row.severity)}</span>
					<span class="alert-rule">${escapeHtml(row.rule_name)}</span>
					<span class="alert-time" data-timestamp="${escapeHtml(row.timestamp)}">${escapeHtml(timestamp)}</span>
				</div>
				<div class="alert-meta">${escapeHtml(row.src_ip)}</div>
				<div class="alert-details" title="${escapeHtml(row.details)}">${escapeHtml(row.details)}</div>
			</li>`;
		})
		.join("");
}

function updatePaginationControls() {
	document.getElementById("page-indicator").textContent = `Page ${state.page} of ${state.totalPages}`;
	document.getElementById("prev-page").disabled = state.page <= 1;
	document.getElementById("next-page").disabled = state.page >= state.totalPages;
}

async function loadAlerts() {
	const severityFilter = document.getElementById("severity-filter");
	const ruleFilter = document.getElementById("rule-filter");

	const params = new URLSearchParams({ page: state.page, page_size: state.pageSize });
	if (severityFilter.value) params.set("severity", severityFilter.value);
	if (ruleFilter.value) params.set("rule_name", ruleFilter.value);

	const response = await fetch(`/api/alerts?${params.toString()}`);
	const data = await response.json();

	state.totalPages = data.total_pages;
	if (state.page > state.totalPages) {
		state.page = state.totalPages;
	}

	renderAlertsTable(data.rows);
	updatePaginationControls();
}

async function loadFilterOptions() {
	const response = await fetch("/api/alerts/filters");
	const options = await response.json();

	const severityFilter = document.getElementById("severity-filter");
	const ruleFilter = document.getElementById("rule-filter");

	for (const severity of options.severities) {
		const option = document.createElement("option");
		option.value = severity;
		option.textContent = severity;
		severityFilter.appendChild(option);
	}

	for (const ruleName of options.rule_names) {
		const option = document.createElement("option");
		option.value = ruleName;
		option.textContent = ruleName;
		ruleFilter.appendChild(option);
	}
}

function changePage(delta) {
	const nextPage = state.page + delta;
	if (nextPage < 1 || nextPage > state.totalPages) return;
	state.page = nextPage;
	loadAlerts();
}

document.addEventListener("DOMContentLoaded", async () => {
	loadActivity();

	const now = new Date();
	volumeState.year = now.getUTCFullYear();
	volumeState.month = now.getUTCMonth() + 1;
	loadVolume();

	await loadFilterOptions();
	loadAlerts();

	document.getElementById("severity-filter").addEventListener("change", () => {
		state.page = 1;
		loadAlerts();
	});
	document.getElementById("rule-filter").addEventListener("change", () => {
		state.page = 1;
		loadAlerts();
	});
	document.getElementById("prev-page").addEventListener("click", () => changePage(-1));
	document.getElementById("next-page").addEventListener("click", () => changePage(1));
	document.getElementById("volume-prev").addEventListener("click", () => changeVolumeMonth(-1));
	document.getElementById("volume-next").addEventListener("click", () => changeVolumeMonth(1));

	document.getElementById("alerts-list").addEventListener("click", (event) => {
		const target = event.target.closest(".alert-time");
		if (!target) return;
		highlightChartTimestamp(target.dataset.timestamp);
	});
});
