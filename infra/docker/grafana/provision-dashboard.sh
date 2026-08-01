#!/bin/sh
set -eu

GRAFANA_URL="${GRAFANA_URL:-http://grafana:3000}"
DASHBOARD_FILE="${DASHBOARD_FILE:-/dashboards/honeypot-dash.json}"
DASHBOARD_NAME="${DASHBOARD_NAME:-adjpgcv}"
NAMESPACE="default"
RESOURCE="apis/dashboard.grafana.app/v2/namespaces/${NAMESPACE}/dashboards"

echo "Waiting for Grafana at ${GRAFANA_URL} ..."
i=0
until curl -sf -o /dev/null "${GRAFANA_URL}/api/health" || [ "$i" -ge 30 ]; do
	i=$((i + 1))
	sleep 2
done
if ! curl -sf -o /dev/null "${GRAFANA_URL}/api/health"; then
	echo "Grafana never became healthy, giving up."
	exit 1
fi
echo "Grafana is up."

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
	-H "Authorization: Bearer ${GRAFANA_SA_TOKEN}" \
	"${GRAFANA_URL}/${RESOURCE}/${DASHBOARD_NAME}")

if [ "$STATUS" = "200" ]; then
	echo "Dashboard '${DASHBOARD_NAME}' exists, updating..."
	METHOD="PUT"
	URL="${GRAFANA_URL}/${RESOURCE}/${DASHBOARD_NAME}"
else
	echo "Dashboard '${DASHBOARD_NAME}' not found, creating..."
	METHOD="POST"
	URL="${GRAFANA_URL}/${RESOURCE}"
fi

RESPONSE_STATUS=$(curl -s -o /tmp/response.json -w "%{http_code}" -X "$METHOD" \
	-H "Authorization: Bearer ${GRAFANA_SA_TOKEN}" \
	-H "Content-Type: application/json" \
	--data @"${DASHBOARD_FILE}" \
	"$URL")

echo "Provisioning request finished with status ${RESPONSE_STATUS}"
cat /tmp/response.json
echo

case "$RESPONSE_STATUS" in
	200 | 201)
		echo "Dashboard provisioned successfully."
		exit 0
		;;
	*)
		echo "Dashboard provisioning FAILED."
		exit 1
		;;
esac
