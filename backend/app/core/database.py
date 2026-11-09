import logging
from pathlib import Path
from typing import Any, Dict, Generator, Optional
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from app.core.config import settings

logger = logging.getLogger("threatlens.database")

Base = declarative_base()

ACTIVE_DATABASE_URL: str = settings.DATABASE_URL
ACTIVE_DB_BACKEND: str = "postgresql"
LAST_POSTGRES_ERROR: Optional[str] = None


def normalize_postgres_url(db_url: str) -> str:
    if db_url.startswith("postgres://"):
        return db_url.replace("postgres://", "postgresql+psycopg://", 1)
    if (
        db_url.startswith("postgresql://")
        and "+psycopg" not in db_url
        and "+psycopg2" not in db_url
    ):
        return db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return db_url


def probe_postgresql_connection() -> Dict[str, Any]:
    """Performs a live connection check against the configured PostgreSQL DATABASE_URL."""
    pg_url = normalize_postgres_url(settings.DATABASE_URL)
    if pg_url.startswith("sqlite"):
        return {
            "configured_dialect": "sqlite",
            "postgresql_connected": False,
            "version": None,
            "error": "DATABASE_URL is configured for SQLite, not PostgreSQL.",
        }

    try:
        probe_engine = create_engine(
            pg_url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 2},
        )
        with probe_engine.connect() as conn:
            ver = conn.execute(text("SELECT version()")).scalar()
        probe_engine.dispose()
        return {
            "configured_dialect": "postgresql",
            "postgresql_connected": True,
            "version": str(ver) if ver else "PostgreSQL",
            "error": None,
        }
    except Exception as exc:
        return {
            "configured_dialect": "postgresql",
            "postgresql_connected": False,
            "version": None,
            "error": str(exc).splitlines()[0] if str(exc) else "Connection refused",
        }


def _create_database_engine():
    global ACTIVE_DATABASE_URL, ACTIVE_DB_BACKEND, LAST_POSTGRES_ERROR
    db_url = normalize_postgres_url(settings.DATABASE_URL)

    if db_url.startswith("sqlite"):
        ACTIVE_DATABASE_URL = db_url
        ACTIVE_DB_BACKEND = "sqlite"
        LAST_POSTGRES_ERROR = "Configured for SQLite"
        eng = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True,
        )
        _enable_sqlite_foreign_keys(eng)
        return eng

    # Attempt real PostgreSQL connection
    try:
        eng = create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            connect_args={"connect_timeout": 3},
        )
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        ACTIVE_DATABASE_URL = db_url
        ACTIVE_DB_BACKEND = "postgresql"
        LAST_POSTGRES_ERROR = None
        logger.info("Connected to PostgreSQL database successfully.")
        return eng
    except Exception as exc:
        LAST_POSTGRES_ERROR = str(exc).splitlines()[0] if str(exc) else "PostgreSQL unreachable"
        if not settings.ALLOW_SQLITE_FALLBACK:
            raise
        db_file = Path(__file__).resolve().parents[2] / "threatlens.db"
        fallback_url = f"sqlite:///{db_file.as_posix()}"
        logger.warning(
            "PostgreSQL at %s is currently unreachable (%s). Using local SQLite fallback at %s until PostgreSQL is started.",
            db_url.split("@")[-1] if "@" in db_url else db_url,
            LAST_POSTGRES_ERROR,
            fallback_url,
        )
        ACTIVE_DATABASE_URL = fallback_url
        ACTIVE_DB_BACKEND = "sqlite_fallback"
        eng = create_engine(
            fallback_url,
            connect_args={"check_same_thread": False},
            pool_pre_ping=True,
        )
        _enable_sqlite_foreign_keys(eng)
        return eng


def _enable_sqlite_foreign_keys(eng):
    @event.listens_for(eng, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


engine = _create_database_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
