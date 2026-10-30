"""E3 SQL Injection runner (V2.2 spec sections 15 / 28 / 22).

prepare(seed) -> baseline(vulnerable) -> fixed(parameterized) -> containment
(least-privilege role) -> regression -> evidence -> verdict.

All queries run against the isolated project-owned lab DB via the restricted
``iot_search_reader`` role (scope section 0). No destructive exploitation.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg  # noqa: E402

from labs.common.evidence import relative_evidence_path, start_run  # noqa: E402
from labs.common.result_schema import ExperimentReport, ScenarioResult, Verdict  # noqa: E402
from labs.e3_sqli import db  # noqa: E402
from labs.e3_sqli.safe import safe_search  # noqa: E402
from labs.e3_sqli.vulnerable import build_vulnerable_sql, vulnerable_search  # noqa: E402

ATTACKER = "can reach the Backend API and supply malicious input"
TB = "TB-C (code/data boundary + database authorization)"

NORMAL_INPUT = "sensor-alpha"
INJECTION_INPUT = "' OR '1'='1"
# UNION read of a sensitive table (4 cols to match devices); role must deny it.
UNION_USERS = "' UNION SELECT id, username, password, 'x' FROM users --"


def _r(sid, expected, actual, control, ok, ev, detail) -> ScenarioResult:
    return ScenarioResult(
        experiment_id="e3", scenario_id=sid, attacker_model=ATTACKER,
        trust_boundary=TB, expected_result=expected, actual_result=actual,
        security_control=control, evidence_location=ev,
        verdict=Verdict.PASS if ok else Verdict.FAIL, detail=detail,
    )


def _denied(conn, sql: str) -> tuple[bool, str]:
    """Run SQL as reader; return (was_denied, message)."""
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            try:
                cur.fetchall()
            except psycopg.ProgrammingError:
                pass
        return False, "executed (NOT denied)"
    except psycopg.errors.InsufficientPrivilege as exc:
        return True, f"InsufficientPrivilege: {str(exc).splitlines()[0]}"
    except psycopg.Error as exc:
        return False, f"other error: {type(exc).__name__}: {str(exc).splitlines()[0]}"


def main() -> int:
    run = start_run("e3")
    ev = relative_evidence_path(run.dir)
    results: list[ScenarioResult] = []

    db.seed()

    # DB state fingerprint (before)
    with db.connect_admin() as admin, admin.cursor() as cur:
        cur.execute("SELECT count(*) FROM devices")
        devices_before = cur.fetchone()[0]

    reader = db.connect_reader()

    # --- Vulnerable baseline: input changes query semantics ---
    normal_rows = vulnerable_search(reader, NORMAL_INPUT)
    inj_rows = vulnerable_search(reader, INJECTION_INPUT)
    run.write_text("E3-01_user_input.txt",
                   f"normal={NORMAL_INPUT!r}\ninjection={INJECTION_INPUT!r}\n")
    run.write_text("E3-02_generated_sql.txt",
                   build_vulnerable_sql(NORMAL_INPUT) + "\n"
                   + build_vulnerable_sql(INJECTION_INPUT) + "\n")
    results.append(_r(
        "E3-VULN-SEMANTICS", "INPUT_CHANGES_QUERY_SEMANTICS=YES",
        f"normal_rows={len(normal_rows)} injected_rows={len(inj_rows)}",
        "none (raw string interpolation baseline)",
        len(inj_rows) > len(normal_rows), ev,
        {"normal_rows": normal_rows, "injected_rows": inj_rows},
    ))

    # --- Fixed mode: parameterized query, same input no longer changes semantics ---
    safe_normal = safe_search(reader, NORMAL_INPUT)
    safe_inj = safe_search(reader, INJECTION_INPUT)
    results.append(_r(
        "E3-FIXED-PARAMETERIZED", "SAME_INPUT_CHANGES_QUERY=NO (PREVENT)",
        f"param_normal_rows={len(safe_normal)} param_injection_rows={len(safe_inj)}",
        "parameterized query", len(safe_inj) == 0 and len(safe_normal) == 1, ev,
        {"param_normal": safe_normal, "param_injection": safe_inj},
    ))

    # --- Containment: least-privilege role (CONTAIN) ---
    allowed_dev = vulnerable_search(reader, NORMAL_INPUT)
    with reader.cursor() as cur:
        cur.execute("SELECT count(*) FROM telemetry")
        tel = cur.fetchone()[0]
    results.append(_r(
        "E3-CONTAIN-ALLOWED-SELECT", "Allowed-table SELECT permitted",
        f"devices_rows={len(allowed_dev)} telemetry_rows={tel}",
        "role GRANT SELECT devices,telemetry", len(allowed_dev) == 1 and tel >= 1,
        ev, {"telemetry_count": tel},
    ))

    denied_union, msg_union = _denied(reader, build_vulnerable_sql(UNION_USERS))
    results.append(_r(
        "E3-CONTAIN-SENSITIVE-READ", "SENSITIVE_TABLE_READ=DENIED",
        msg_union, "role has no SELECT on users/secrets/audit_internal",
        denied_union, ev, {"injection": UNION_USERS},
    ))

    denied_upd, msg_upd = _denied(
        reader, "UPDATE devices SET status='hacked' WHERE id=1")
    results.append(_r(
        "E3-CONTAIN-UNAUTH-UPDATE", "UNAUTHORIZED_UPDATE=DENIED", msg_upd,
        "role has no UPDATE", denied_upd, ev, {},
    ))

    denied_drop, msg_drop = _denied(reader, "DROP TABLE devices")
    results.append(_r(
        "E3-CONTAIN-UNAUTH-DROP", "UNAUTHORIZED_DROP=DENIED", msg_drop,
        "role has no DROP/DDL", denied_drop, ev, {},
    ))

    # --- DB state unchanged + normal regression ---
    with db.connect_admin() as admin, admin.cursor() as cur:
        cur.execute("SELECT count(*) FROM devices")
        devices_after = cur.fetchone()[0]
    results.append(_r(
        "E3-DB-STATE", "DB state before == after",
        f"before={devices_before} after={devices_after}",
        "non-destructive testing", devices_before == devices_after, ev, {},
    ))

    reg = safe_search(reader, NORMAL_INPUT)
    results.append(_r(
        "E3-REGRESSION", "NORMAL_DEVICE_SEARCH=PASS",
        f"rows={len(reg)} name={reg[0][1] if reg else None}",
        "parameterized query", len(reg) == 1 and reg[0][1] == NORMAL_INPUT, ev,
        {"rows": reg},
    ))

    reader.close()

    report = ExperimentReport("e3", run.run_id, tuple(results))
    run.write_json("result.json", report.to_dict())

    print(f"=== E3 SQL Injection | run {run.run_id} | verdict {report.verdict.value} ===")
    for s in results:
        print(f"  [{s.verdict.value:4}] {s.scenario_id}: {s.actual_result}")
    print(f"Evidence: {run.dir}")
    return 0 if report.verdict == Verdict.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
