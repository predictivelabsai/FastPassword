"""Database backend abstraction — PostgreSQL (default) or SQLite.

Toggle with ``DB_TYPE`` (``postgresql`` | ``sqlite``). SQL is written once using
``?`` placeholders and a ``{PK}`` token for the auto-increment primary key; this
layer translates for the active backend. All timestamps are stored as ISO-8601
TEXT for portability.

PostgreSQL config:
  DB_TYPE=postgresql
  DATABASE_URL=...            (falls back to DATABASE_URL_PROD)
  DB_SCHEMA=fast_password     (created on init; used as search_path)

SQLite config:
  DB_TYPE=sqlite
  FASTPASSWORD_DB=data/fastpassword.sqlite
"""
from __future__ import annotations
import os
from contextlib import contextmanager
from pathlib import Path

BACKEND = os.getenv("DB_TYPE", "postgresql").strip().lower()
IS_PG = BACKEND.startswith("post")

if IS_PG:
    import psycopg
    from psycopg.rows import dict_row

    DB_SCHEMA = os.getenv("DB_SCHEMA", "fast_password")

    def _dsn():
        dsn = os.getenv("DATABASE_URL") or os.getenv("DATABASE_URL_PROD") or ""
        if not dsn:
            raise RuntimeError("DATABASE_URL (or DATABASE_URL_PROD) required for DB_TYPE=postgresql")
        if dsn.startswith("postgres://"):
            dsn = "postgresql://" + dsn[len("postgres://"):]
        return dsn

    PK = "BIGSERIAL PRIMARY KEY"

    def _translate(sql: str) -> str:
        return sql.replace("?", "%s")

    _CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))

    def _connect():
        conn = psycopg.connect(_dsn(), autocommit=False, row_factory=dict_row,
                               connect_timeout=_CONNECT_TIMEOUT)
        conn.execute(f"SET search_path TO {DB_SCHEMA}, public")
        return conn
else:
    import sqlite3

    PK = "INTEGER PRIMARY KEY"

    def _translate(sql: str) -> str:
        return sql

    def _connect():
        path = Path(os.getenv("FASTPASSWORD_DB", "data/fastpassword.sqlite"))
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn


class Session:
    """Thin wrapper giving a uniform execute/insert over one open connection."""

    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql, args=()):
        return self.conn.execute(_translate(sql), tuple(args))

    def insert(self, sql, args=()):
        if IS_PG:
            cur = self.conn.execute(_translate(sql) + " RETURNING id", tuple(args))
            return cur.fetchone()["id"]
        return self.conn.execute(sql, tuple(args)).lastrowid

    def fetchall(self, sql, args=()):
        return [dict(r) for r in self.execute(sql, args).fetchall()]

    def fetchone(self, sql, args=()):
        found = self.execute(sql, args).fetchone()
        return dict(found) if found else None


@contextmanager
def tx():
    conn = _connect()
    try:
        yield Session(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def rows(sql, args=()):
    with tx() as s:
        return s.fetchall(sql, args)


def row(sql, args=()):
    with tx() as s:
        return s.fetchone(sql, args)


def execute(sql, args=()):
    with tx() as s:
        s.execute(sql, args)


def insert(sql, args=()):
    with tx() as s:
        return s.insert(sql, args)


def init_schema(schema_sql: str):
    """Create the schema (Postgres) and all tables; runs each statement portably."""
    with tx() as s:
        if IS_PG:
            s.execute(f"CREATE SCHEMA IF NOT EXISTS {DB_SCHEMA}")
            s.execute(f"SET search_path TO {DB_SCHEMA}, public")
        body = schema_sql.replace("{PK}", PK)
        for statement in body.split(";"):
            if statement.strip():
                s.execute(statement)
