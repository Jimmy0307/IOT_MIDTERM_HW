"""V2.2 Final Acceptance Gates validated against produced evidence (spec 35).

These tests read the latest ``result.json`` written by each runner and assert the
mandatory gates. They require the runners to have been executed first:

    python runners/run_e2.py
    python runners/run_e3.py
    python runners/run_e1.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"


def latest_result(exp: str) -> dict | None:
    base = EVIDENCE / exp
    runs = sorted((p for p in base.glob("*/result.json")), key=lambda p: p.stat().st_mtime)
    if not runs:
        return None
    return json.loads(runs[-1].read_text(encoding="utf-8"))


def scenarios_by_id(result: dict) -> dict[str, dict]:
    return {s["scenario_id"]: s for s in result["scenarios"]}


# ------------------------------- E2 gates -------------------------------

@pytest.mark.acceptance
def test_e2_gate():
    result = latest_result("e2")
    if result is None:
        pytest.skip("run runners/run_e2.py first")
    s = scenarios_by_id(result)
    required = [
        "E2-PROT-FIRST-ACCEPT", "E2-PROT-EXACT-REPLAY", "E2-PROT-MODIFIED-NONCE",
        "E2-PROT-MODIFIED-TIMESTAMP", "E2-PROT-MODIFIED-BODY",
        "E2-PROT-ACTION-STATE", "E2-PROT-AUDIT-LOG",
    ]
    for sid in required:
        assert sid in s, f"missing {sid}"
        assert s[sid]["verdict"] == "PASS", f"{sid} not PASS"
    assert result["verdict"] == "PASS"


# ------------------------------- E3 gates -------------------------------

@pytest.mark.acceptance
def test_e3_gate():
    result = latest_result("e3")
    if result is None:
        pytest.skip("run runners/run_e3.py first (needs lab PostgreSQL)")
    s = scenarios_by_id(result)
    required = [
        "E3-VULN-SEMANTICS", "E3-FIXED-PARAMETERIZED", "E3-CONTAIN-SENSITIVE-READ",
        "E3-CONTAIN-UNAUTH-UPDATE", "E3-CONTAIN-UNAUTH-DROP", "E3-REGRESSION",
    ]
    for sid in required:
        assert sid in s, f"missing {sid}"
        assert s[sid]["verdict"] == "PASS", f"{sid} not PASS"
    assert result["verdict"] == "PASS"


# ------------------------------- E1 gates -------------------------------

@pytest.mark.acceptance
def test_e1_gate_or_documented_fallback():
    result = latest_result("e1")
    if result is None:
        pytest.skip("run runners/run_e1.py first (needs Docker)")
    s = scenarios_by_id(result)
    gate = s.get("E1-FEASIBILITY-GATE")
    assert gate is not None, "feasibility gate must be recorded"
    if gate["verdict"] == "PASS":
        # Full primary experiment gates must then pass.
        for sid in ["E1-MITM-PATH", "E1-HTTPS-PAYLOAD-PROTECTED",
                    "E1-TLS-CERT-VALIDATION", "E1-REGRESSION"]:
            assert s[sid]["verdict"] == "PASS", f"{sid} not PASS"
        assert result["verdict"] == "PASS"
    else:
        # Fallback policy: feasibility FAIL is acceptable IF evidence was frozen
        # and E3 (primary fallback) passed. Spec sections 3 / 33.
        e3 = latest_result("e3")
        assert e3 is not None and e3["verdict"] == "PASS", (
            "E1 feasibility FAILed; fallback requires E3 primary to PASS"
        )
