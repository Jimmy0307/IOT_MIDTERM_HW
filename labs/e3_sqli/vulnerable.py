"""VULNERABLE baseline: genuine raw SQL with direct string interpolation.

Spec section 21.1 (FROZEN): the baseline must be a *true* raw SQL +
user-controlled string interpolation - NOT parameter binding or a safe ORM
query dressed up as vulnerable.

Scope: runs only against the isolated project-owned lab DB. The query is a
read-only SELECT; no destructive operation is performed (spec section 22).
"""

from __future__ import annotations

import psycopg


def build_vulnerable_sql(user_input: str) -> str:
    """Build the query by directly interpolating untrusted input (the bug)."""
    # This is the vulnerability: user_input becomes part of the SQL text.
    return f"SELECT id, name, location, status FROM devices WHERE name = '{user_input}'"


def vulnerable_search(conn: psycopg.Connection, user_input: str) -> list[tuple]:
    """Execute the interpolated query and return rows."""
    sql = build_vulnerable_sql(user_input)
    with conn.cursor() as cur:
        cur.execute(sql)  # noqa: S608 - intentional vulnerable baseline
        return cur.fetchall()
