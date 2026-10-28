"""FIXED mode: parameterized query (spec sections 24 / 27 - PREVENT).

Separates SQL code from user-controlled data, so the same input that changed
query semantics in the vulnerable baseline is now treated purely as a value.
"""

from __future__ import annotations

import psycopg

# SQL code is fixed; the user value is bound as a parameter, never concatenated.
SAFE_SQL = "SELECT id, name, location, status FROM devices WHERE name = %s"


def safe_search(conn: psycopg.Connection, user_input: str) -> list[tuple]:
    with conn.cursor() as cur:
        cur.execute(SAFE_SQL, (user_input,))
        return cur.fetchall()
