import os

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

import engine.config  # noqa: F401  (loads DATABASE_URL from the project .env)
from engine.db.models import Base

target_metadata = Base.metadata


def _get_database_url() -> str:
	database_url = os.getenv("DATABASE_URL")
	if not database_url:
		raise RuntimeError("DATABASE_URL is not set")
	return database_url


def _run_with_connection(connection: Connection) -> None:
	context.configure(
		connection=connection,
		target_metadata=target_metadata,
		# SQLite can't ALTER most things in place; batch mode rebuilds the table.
		render_as_batch=connection.dialect.name == "sqlite",
	)
	with context.begin_transaction():
		context.run_migrations()


def run_migrations_offline() -> None:
	context.configure(
		url=_get_database_url(),
		target_metadata=target_metadata,
		literal_binds=True,
		dialect_opts={"paramstyle": "named"},
	)
	with context.begin_transaction():
		context.run_migrations()


def run_migrations_online() -> None:
	# engine.db.migrate.upgrade_to_head() hands over its own connection.
	connection = context.config.attributes.get("connection")
	if connection is not None:
		_run_with_connection(connection)
		return

	connectable = create_engine(_get_database_url(), future=True)
	with connectable.connect() as connection:
		_run_with_connection(connection)


if context.is_offline_mode():
	run_migrations_offline()
else:
	run_migrations_online()
