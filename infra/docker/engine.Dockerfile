FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY engine/requirements.txt /tmp/engine-requirements.txt
RUN pip install --no-cache-dir -r /tmp/engine-requirements.txt

COPY engine /app/engine

WORKDIR /app
ENV PYTHONPATH=/app

CMD ["python", "-m", "engine.main"]