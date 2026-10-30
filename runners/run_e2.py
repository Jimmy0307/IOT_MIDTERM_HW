"""E2 Replay runner (V2.2 spec sections 15 / 20 / 22).

prepare -> baseline (vulnerable) -> controlled test (protected) -> evidence ->
verdict. Drives the lab in-process via FastAPI TestClient for deterministic,
reproducible evidence (no external network, scope section 0).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from labs.common.evidence import relative_evidence_path, start_run  # noqa: E402
from labs.common.result_schema import ExperimentReport, ScenarioResult, Verdict  # noqa: E402
from labs.e2_replay.client import build_signed_request, make_nonce  # noqa: E402
from labs.e2_replay.server import ReplayLab, create_app  # noqa: E402

DEVICE = "dispenser-01"
SECRET = b"DEMO_LOCAL_ONLY_device_secret_dispenser_01"
PATH = "/protected/dispense"
ATTACKER = "holds one captured legitimate request (log leak / post-TLS internal)"
TB = "TB-B / TB-D (message authentication + freshness)"


def _r(scenario: str, expected: str, actual: str, control: str, ok: bool,
       ev: str, detail: dict) -> ScenarioResult:
    return ScenarioResult(
        experiment_id="e2", scenario_id=scenario, attacker_model=ATTACKER,
        trust_boundary=TB, expected_result=expected, actual_result=actual,
        security_control=control, evidence_location=ev,
        verdict=Verdict.PASS if ok else Verdict.FAIL, detail=detail,
    )


def main() -> int:
    run = start_run("e2")
    ev = relative_evidence_path(run.dir)
    results: list[ScenarioResult] = []

    # --- Baseline: vulnerable mode, exact replay accepted ---
    vlab = ReplayLab()
    vc = TestClient(create_app(vlab))
    body = b'{"device_id":"dispenser-01"}'
    h = {"content-type": "application/json"}
    c1 = vc.post("/vulnerable/dispense", content=body, headers=h).json()
    c2 = vc.post("/vulnerable/dispense", content=body, headers=h).json()
    results.append(_r(
        "E2-VULN-EXACT-REPLAY", "EXACT_REPLAY=ACCEPT, ACTION_COUNT=2",
        f"first={c1['action_count']} replay={c2['action_count']}",
        "none (vulnerable baseline)",
        c1["action_count"] == 1 and c2["action_count"] == 2, ev,
        {"first": c1, "replay": c2},
    ))

    # --- Protected mode ---
    lab = ReplayLab()
    pc = TestClient(create_app(lab))

    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    first = pc.post(PATH, content=raw, headers=headers)
    results.append(_r(
        "E2-PROT-FIRST-ACCEPT", "FIRST_REQUEST=ACCEPT (action_count=1)",
        f"status={first.json()['status']} count={first.json().get('action_count')}",
        "HMAC(raw body)+timestamp+nonce", first.status_code == 200
        and first.json().get("action_count") == 1, ev, {"resp": first.json()},
    ))

    exact = pc.post(PATH, content=raw, headers=headers)
    results.append(_r(
        "E2-PROT-EXACT-REPLAY", "EXACT_REPLAY=REJECT",
        f"status={exact.status_code} reason={exact.json().get('reason')}",
        "nonce cache", exact.status_code == 401, ev, {"resp": exact.json()},
    ))

    tn = dict(headers); tn["x-nonce"] = make_nonce()
    mn = pc.post(PATH, content=raw, headers=tn)
    results.append(_r(
        "E2-PROT-MODIFIED-NONCE", "MODIFIED_NONCE_OLD_SIGNATURE=REJECT",
        f"status={mn.status_code} reason={mn.json().get('reason')}",
        "HMAC covers nonce", mn.status_code == 401
        and mn.json().get("reason") == "signature mismatch", ev, {"resp": mn.json()},
    ))

    import time as _t
    tt = dict(headers); tt["x-nonce"] = make_nonce()
    tt["x-timestamp"] = str(int(_t.time()) + 1)
    mt = pc.post(PATH, content=raw, headers=tt)
    results.append(_r(
        "E2-PROT-MODIFIED-TIMESTAMP", "MODIFIED_TIMESTAMP_OLD_SIGNATURE=REJECT",
        f"status={mt.status_code} reason={mt.json().get('reason')}",
        "HMAC covers timestamp", mt.status_code == 401
        and mt.json().get("reason") == "signature mismatch", ev, {"resp": mt.json()},
    ))

    tb = dict(headers); tb["x-nonce"] = make_nonce()
    mb = pc.post(PATH, content=b'{"cmd":"DISPENSE","qty":999}', headers=tb)
    results.append(_r(
        "E2-PROT-MODIFIED-BODY", "MODIFIED_BODY_OLD_SIGNATURE=REJECT",
        f"status={mb.status_code} reason={mb.json().get('reason')}",
        "HMAC covers raw body", mb.status_code == 401
        and mb.json().get("reason") == "signature mismatch", ev, {"resp": mb.json()},
    ))

    count = lab.device(DEVICE).action_count
    results.append(_r(
        "E2-PROT-ACTION-STATE", "ACTION_COUNT_ON_REPLAY=UNCHANGED (=1)",
        f"action_count={count}", "replay protection", count == 1, ev,
        {"action_count": count},
    ))

    results.append(_r(
        "E2-PROT-AUDIT-LOG", "AUDIT_LOG_CREATED=YES",
        f"events={len(lab.audit_log)}", "audit logging",
        any(e["event"] == "ACCEPT" for e in lab.audit_log)
        and any(e["event"] == "REJECT" for e in lab.audit_log), ev,
        {"audit_sample": lab.audit_log[:6]},
    ))

    report = ExperimentReport("e2", run.run_id, tuple(results))
    run.write_json("result.json", report.to_dict())
    run.write_json("audit_log.json", lab.audit_log)
    run.write_json("device_history.json", lab.device(DEVICE).history)

    print(f"=== E2 Replay | run {run.run_id} | verdict {report.verdict.value} ===")
    for s in results:
        print(f"  [{s.verdict.value:4}] {s.scenario_id}: {s.actual_result}")
    print(f"Evidence: {run.dir}")
    return 0 if report.verdict == Verdict.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
