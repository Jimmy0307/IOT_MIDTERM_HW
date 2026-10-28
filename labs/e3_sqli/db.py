"""E3 database connection helpers (psycopg3).

Two DSNs model the application's two trust levels:
  - admin DSN: owns the schema, used only for seeding / verifying DB state.
  - reader DSN: the restricted ``iot_search_reader`` role the API uses at
    runtime (least privilege, spec section 25).
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg

_DEFAULT_ADMIN = "postgresql://postgres:postgres@127.0.0.1:55432/iotlab"
_DEFAULT_READER = (
    "postgresql://iot_search_reader:DEMO_LOCAL_ONLY_reader_pw@127.0.0.1:55432/iotlab"
)

SEED_SQL = Path(__file__).with_name("seed.sql")


def admin_dsn() -> str:
    return os.environ.get("E3_ADMIN_DSN", _DEFAULT_ADMIN)


def reader_dsn() -> str:
    return os.environ.get("E3_READER_DSN", _DEFAULT_READER)


def connect_admin() -> psycopg.Connection:
    return psycopg.connect(admin_dsn(), autocommit=True)


def connect_reader() -> psycopg.Connection:
    return psycopg.connect(reader_dsn(), autocommit=True)


def seed() -> None:
    """(Re)create schema, data and the restricted role using the admin DSN."""
    sql = SEED_SQL.read_text(encoding="utf-8")
    with connect_admin() as conn, conn.cursor() as cur:
        cur.execute(sql)
