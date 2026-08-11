FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY engine/requirements.txt /tmp/engine-requirements.txt
RUN pip install --no-cache-dir -r /tmp/engine-requirements.txt

COPY engine /app/engine

ENV PYTHONPATH=/app

ARG ENGINE_UID=1000
ARG ENGINE_GID=1000

RUN set -eux; \
	if ! getent group "${ENGINE_GID}" >/dev/null; then \
		groupadd --gid "${ENGINE_GID}" engine; \
	fi; \
	if ! getent passwd "${ENGINE_UID}" >/dev/null; then \
		useradd --uid "${ENGINE_UID}" --gid "${ENGINE_GID}" \
			--no-create-home --shell /usr/sbin/nologin engine; \
	fi
USER ${ENGINE_UID}:${ENGINE_GID}

CMD ["python", "-m", "engine.main"]
