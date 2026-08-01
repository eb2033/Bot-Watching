FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY dashboard/requirements.txt /tmp/dashboard-requirements.txt
RUN pip install --no-cache-dir -r /tmp/dashboard-requirements.txt

# The dashboard only reads through engine.db (models/session) , copy just that
# instead of the whole engine/ package, which also carries the ~75MB GeoIP
# database that the dashboard never touches.
COPY engine/__init__.py /app/engine/__init__.py
COPY engine/db /app/engine/db
COPY dashboard /app/dashboard

ENV PYTHONPATH=/app

EXPOSE 5000

CMD ["python", "-m", "dashboard.app"]
