"""E3 SQL Injection acceptance tests (V2.2 spec sections 28 / 22).

Requires the lab PostgreSQL (docker compose up -d postgres). Tests are skipped
if the DB is unreachable so the rest of the suite still runs.
"""

from __future__ import annotations

import psycopg
import pytest

from labs.e3_sqli import db
from labs.e3_sqli.safe import safe_search
from labs.e3_sqli.vulnerable import build_vulnerable_sql, vulnerable_search

NORMAL = "sensor-alpha"
INJECTION = "' OR '1'='1"
UNION_USERS = "' UNION SELECT id, username, password, 'x' FROM users --"


def _db_available() -> bool:
    try:
        with db.connect_admin():
            return True
    except psycopg.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _db_available(), reason="lab PostgreSQL not reachable (docker compose up -d postgres)"
)


@pytest.fixture(scope="module", autouse=True)
def seeded() -> None:
    db.seed()


@pytest.fixture
def reader() -> psycopg.Connection:
    conn = db.connect_reader()
    yield conn
    conn.close()


@pytest.mark.acceptance
def test_true_raw_sql_baseline_interpolates_input():
    """The baseline must be genuine string interpolation (spec 21.1)."""
    sql = build_vulnerable_sql(INJECTION)
    assert INJECTION in sql
    assert "%s" not in sql  # not parameterized


@pytest.mark.acceptance
def test_injection_changes_query_semantics(reader):
    normal = vulnerable_search(reader, NORMAL)
    injected = vulnerable_search(reader, INJECTION)
    assert len(normal) == 1
    assert len(injected) > len(normal)  # QUERY_SEMANTICS_MANIPULATION = VERIFIED


@pytest.mark.acceptance
def test_parameterized_query_prevents_injection(reader):
    assert len(safe_search(reader, NORMAL)) == 1
    assert len(safe_search(reader, INJECTION)) == 0  # PARAMETERIZED_QUERY = PASS


@pytest.mark.acceptance
def test_sensitive_table_read_denied(reader):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        vulnerable_search(reader, UNION_USERS)  # SENSITIVE_TABLE_READ = DENIED


@pytest.mark.acceptance
def test_unauthorized_update_denied(reader):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with reader.cursor() as cur:
            cur.execute("UPDATE devices SET status='x' WHERE id=1")


@pytest.mark.acceptance
def test_unauthorized_drop_denied(reader):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with reader.cursor() as cur:
            cur.execute("DROP TABLE devices")


@pytest.mark.acceptance
def test_normal_query_regression(reader):
    rows = safe_search(reader, NORMAL)
    assert len(rows) == 1 and rows[0][1] == NORMAL  # NORMAL_QUERY_REGRESSION = PASS
