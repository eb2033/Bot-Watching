from contextlib import contextmanager
import os
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


engine = None
SessionLocal: Optional[sessionmaker] = None


def _get_database_url() -> str:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")
    return database_url


def get_engine():
    global engine, SessionLocal
    database_url = _get_database_url()
    if engine is None or str(engine.url) != database_url:
        # SQLALCHEMY_DEBUG is opt-in for local debugging only: echo=True logs
        # every statement with its bound parameters, and this pipeline inserts
        # attacker-supplied usernames/passwords - so leaving it on writes
        # captured credentials into container logs and any cloud aggregator
        # downstream.
        engine = create_engine(database_url, echo=os.getenv("SQLALCHEMY_DEBUG") == "1", future=True)
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return engine


def get_session_local():
    if SessionLocal is None:
        get_engine()
    return SessionLocal


@contextmanager
def get_db_session():
    session_factory = get_session_local()
    if session_factory is None:
        raise RuntimeError("SessionLocal is not initialized")
    db = session_factory()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

