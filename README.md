# Bot-Watching

Have you ever wondered how those automated scanning bots work over the web? Now you can throw out some bait and watch what they do in (almost) real time.

Bot-Watching is a Cowrie honeypot monitoring pipeline — like birdwatching, but the "birds" are automated scanners, credential-stuffing bots, and opportunistic attackers. Logs are parsed, filtered, and enriched in Python, persisted to PostgreSQL, and visualized in **Grafana**.

## Overview

A Cowrie honeypot emulates a vulnerable SSH/Telnet host and logs every session as JSON — the "feeder," drawing in whatever's out there. A local Python **engine** consumes those logs, normalizes them into typed events, applies detection rules (bad credentials, brute force, suspicious commands, file downloads), enriches source IPs with geolocation (GeoLite2), and persists everything to PostgreSQL. **Grafana**, connected read-only to that same database, is where you actually look at the data: attacker volume over time, alert severity, source geography, credentials attempted, and so on.

The target production architecture ships Cowrie on AWS EC2, landing raw logs in S3 and notifying the engine via SQS. That wiring isn't built yet — see [Current state](#current-state) below for what's real today versus what's still ahead.

## Architecture

```
Cowrie (SSH/Telnet honeypot)
        │  JSON session logs
        ▼
engine/  — parse → filter/detect → enrich (GeoLite2) → persist
        │
        ▼
PostgreSQL (SQLAlchemy models: sessions, auth_attempts, commands,
            downloads, alerts, ip_enrichment)
        │
        ▼
Grafana  — dashboards over a read-only DB role
```

- **Cowrie** — emulates a vulnerable SSH/Telnet host, logs every session as JSON.
- **engine/** — parses Cowrie's JSON event types, runs detection rules, enriches source IPs, writes normalized rows to Postgres.
- **PostgreSQL** — normalized storage; Grafana connects through a dedicated, `SELECT`-only role rather than the engine's own credentials.
- **Grafana** — the current visualization layer, run via Docker Compose alongside the DB.

### Current state

- `engine/` is the most developed and tested part of the repo: parsing, filtering/detection, DB models, string sanitization, IP enrichment, and pytest coverage are all in place.
- The target ingestion path is Cowrie → S3 → SQS → engine. That's not wired up yet. Today, [engine/listener.py](engine/listener.py) reads Cowrie JSON lines directly from a local file (`COWRIE_LOG_PATH`, batched via `LISTENER_BATCH_SIZE`) to emulate SQS polling locally — see [engine/main.py](engine/main.py).
- IP enrichment (`engine/enrichment/enrichment.py`) looks up `country`/`city`/`asn`/`org` (and now real `latitude`/`longitude`) per source IP via GeoLite2, caching results in the `ip_enrichment` table so each IP is only looked up once.
- **Grafana is the visualization layer.** `infra/docker/docker-compose.yml` runs a `grafana` service alongside Postgres, with SSL between them and a least-privilege `SELECT`-only DB role created for it (`infra/docker/init-scripts/create-grafana-user.sh`). The earlier home-built Flask + Plotly + Mapbox dashboard has been retired in favor of it.
- `scripts/seed_sample_traffic.py` writes synthetic Cowrie JSONL with real, GeoLite2-resolvable public IPs across all continents straight into `COWRIE_LOG_PATH`, so the pipeline can be exercised end-to-end without waiting on real attacker traffic — genuine local/private-range traffic never resolves to a location, so this is the only way to get geolocatable data locally. (An earlier idea to drive real brute-force traffic via a dedicated `attacker` container is retired; `infra/docker/attacker.Dockerfile` still exists on disk but isn't part of the Compose stack.)

## Repository Structure

```
engine/                     # Python: log ingestion -> parsing -> filtering -> enrichment -> DB
├── config.py                # shared paths/env (wordlists, DATABASE_URL)
├── listener.py               # local-file batch reader (target: SQS long-poll)
├── main.py                   # poll -> parse -> filter -> enrich -> persist loop
├── parser/                   # eventid -> normalized Pydantic event schemas
├── enrichment/                # GeoLite2 IP -> country/city/asn/org/lat/lon
│   └── data/                   # GeoLite2-City.mmdb / GeoLite2-ASN.mmdb
├── filters/                  # bad-creds, brute-force, command, download-severity rules
│   └── wordlists/              # usernames.txt, PasswordTop1000.txt (SecLists)
├── db/                        # SQLAlchemy models, sanitization, session, CRUD
└── tests/                    # pytest suite

scripts/
└── seed_sample_traffic.py    # synthetic Cowrie JSONL w/ real public IPs, for local testing

infra/
├── docker/                   # engine.Dockerfile, db.Dockerfile, docker-compose.yml
│                              # Postgres SSL certs, Grafana DB-user init script
└── cowrie/                   # cowrie.cfg.example, EC2/S3/SQS notes for the target deployment
```

## Prerequisites

- Python 3.12+
- Docker & Docker Compose
- GeoLite2 `City` and `ASN` `.mmdb` databases (place under `engine/enrichment/data/`) — free from MaxMind with a (free) account
- A PostgreSQL instance (the Docker Compose stack provides one for local dev)

AWS (EC2/S3/SQS) is only required once the target ingestion path is implemented — not needed for local development today.

## Setup (local dev loop)

1. **Clone and configure environment**

   ```bash
   git clone <repo-url>
   cd Honeypot_Project
   cp infra/docker/.env.example infra/docker/.env   # DB + Grafana credentials
   cp .env.example .env 
   ```

2. **Bring up the local stack** (Postgres, Cowrie, engine, and Grafana)

   ```bash
   docker compose -f infra/docker/docker-compose.yml up
   ```

3. **View dashboards in Grafana** at `http://localhost:3000` (default admin credentials come from `GF_SECURITY_ADMIN_USER` / `GF_SECURITY_ADMIN_PASSWORD` in `infra/docker/.env`). Grafana connects to Postgres over SSL using the read-only role provisioned by `create-grafana-user.sh`.

4. **Seed realistic, geolocatable traffic** (real local/private-range traffic never resolves to a location, so this script is what gives the pipeline real, geolocatable public IPs to enrich):

   ```bash
   python scripts/seed_sample_traffic.py [--log-path ...]
   ```

5. **Run the engine locally** (outside Docker, e.g. for debugging):

   ```bash
   cd engine
   pip install -r requirements.txt
   python -m engine.main   # reads COWRIE_LOG_PATH, defaults to /var/log/cowrie/cowrie.json
   ```

## Environment variables

Root `.env` (shared by `engine/`):

```
DATABASE_URL=postgresql+psycopg2://user:password@localhost:5432/honeypot
COWRIE_LOG_PATH=/var/log/cowrie/cowrie.json
LISTENER_BATCH_SIZE=5
LISTENER_POLL_INTERVAL_SECONDS=2
```

`infra/docker/.env` (Compose stack — DB and Grafana credentials):

```
POSTGRES_DB=
POSTGRES_USER=
POSTGRES_PASSWORD=
GRAFANA_USER=
GRAFANA_PASSWORD=
GF_SECURITY_ADMIN_USER=
GF_SECURITY_ADMIN_PASSWORD=
```

## Running tests

```bash
cd engine && python -m pytest tests/ -v   # engine test suite
python engine/tests/run_tests.py           # centralized full suite
```

## Detection rules

Basic heuristics live in `engine/filters/rules.py`: known-bad credential matching against curated wordlists, brute-force detection (5+ failed auth attempts from the same source IP), suspicious command input, and file-download flagging. These are "flags for likely-suspicious patterns," not a full threat-detection engine or SIEM.

## Security considerations

- Run Cowrie on an isolated subnet/network with no access to production resources.
- Treat all honeypot-sourced data as untrusted — attacker-supplied strings (usernames, commands, filenames) are sanitized before being persisted (`engine/db/sanitization.py`), but stay defensive with anything rendered downstream.
- Grafana talks to Postgres over SSL through a dedicated `SELECT`-only role — never the engine's own write credentials.
- Keep secrets (`.env` files, TLS keys/certs under `infra/docker/certs/`) out of version control.

## Scope & limitations

- Built for learning, research, and small-scale monitoring — not a drop-in enterprise security product.
- No high availability: the engine is a single instance with no failover, clustering, or auto-scaling.
- No formal audit logging, compliance controls, or SLAs.
- Detection rules are basic heuristics, not a full SIEM.
- Single honeypot, single region by default; the SQS/S3 ingestion path for a real AWS deployment isn't implemented yet.

## Roadmap

- Deploy Cowrie to AWS and wire up the real S3 → SQS → engine ingestion path (currently emulated by local-file polling).
- Decide the long-term fate of the legacy Flask dashboard (retire vs. keep as a supplementary view). ✔ (Retired)
- Expand detection rules beyond the current heuristic set.

## License

N/A yet
