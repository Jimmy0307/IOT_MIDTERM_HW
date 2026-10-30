"""V2.2 Final Acceptance Gates validated against produced evidence (spec 35).

These tests validate the authoritative final runs pinned in
``evidence/FINAL_MANIFEST.json`` (``e1_run_id`` / ``e2_run_id`` / ``e3_run_id``),
resolving exactly ``evidence/<exp>/<run_id>/result.json``. File timestamps are
never used: clone/extract/copy can change mtimes, so a historical run must not
become authoritative because it looks newer.

A missing manifest, a missing pinned ``result.json``, or a ``result.json`` whose
``experiment_id`` / ``run_id`` disagrees with the manifest is a hard FAIL.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

import pytest

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence"
MANIFEST = EVIDENCE / "FINAL_MANIFEST.json"


class EvidenceResolutionError(AssertionError):
    """The manifest-pinned final evidence cannot be resolved or is inconsistent."""


def load_manifest(path: Path = MANIFEST) -> dict:
    if not path.is_file():
        raise EvidenceResolutionError(f"final manifest missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def pinned_result(exp: str, manifest_path: Path = MANIFEST,
                  evidence_root: Path = EVIDENCE) -> dict:
    """Return the manifest-pinned final ``result.json`` for experiment ``exp``."""
    manifest = load_manifest(manifest_path)
    run_id = manifest.get(f"{exp}_run_id")
    if not run_id:
        raise EvidenceResolutionError(f"manifest has no {exp}_run_id")
    path = evidence_root / exp / run_id / "result.json"
    if not path.is_file():
        raise EvidenceResolutionError(f"pinned evidence missing: {path}")
    result = json.loads(path.read_text(encoding="utf-8"))
    if result.get("experiment_id") != exp:
        raise EvidenceResolutionError(
            f"{path}: experiment_id {result.get('experiment_id')!r} != {exp!r}")
    if result.get("run_id") != run_id:
        raise EvidenceResolutionError(
            f"{path}: run_id {result.get('run_id')!r} != manifest {run_id!r}")
    return result


def scenarios_by_id(result: dict) -> dict[str, dict]:
    return {s["scenario_id"]: s for s in result["scenarios"]}


# ------------------------------- E2 gates -------------------------------

@pytest.mark.acceptance
def test_e2_gate():
    result = pinned_result("e2")
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
    result = pinned_result("e3")
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
    result = pinned_result("e1")
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
        e3 = pinned_result("e3")
        assert e3["verdict"] == "PASS", (
            "E1 feasibility FAILed; fallback requires E3 primary to PASS"
        )


# ----------------------- manifest-pinning guarantees -----------------------

def _copy_evidence(tmp_path: Path, exp: str, run_ids: list[str]) -> Path:
    """Copy the real manifest and selected real result.json files into tmp_path."""
    root = tmp_path / "evidence"
    root.mkdir()
    for rid in run_ids:
        dst = root / exp / rid
        dst.mkdir(parents=True)
        shutil.copy2(EVIDENCE / exp / rid / "result.json", dst / "result.json")
    shutil.copy2(MANIFEST, root / "FINAL_MANIFEST.json")
    return root


def _historical_runs(exp: str, final_run: str) -> list[str]:
    return sorted(p.parent.name for p in (EVIDENCE / exp).glob("*/result.json")
                  if p.parent.name != final_run)


@pytest.mark.parametrize("exp", ["e1", "e2", "e3"])
def test_newer_historical_result_cannot_replace_pinned_run(tmp_path, exp):
    final_run = load_manifest()[f"{exp}_run_id"]
    historical = _historical_runs(exp, final_run)
    assert historical, f"expected historical {exp} runs to exercise this guarantee"
    root = _copy_evidence(tmp_path, exp, [final_run, *historical])
    # Make every historical result.json strictly newer than the pinned one.
    future = time.time() + 3600
    for rid in historical:
        os.utime(root / exp / rid / "result.json", (future, future))
    pinned = root / exp / final_run / "result.json"
    old = time.time() - 3600
    os.utime(pinned, (old, old))

    newest = max((root / exp).glob("*/result.json"), key=lambda p: p.stat().st_mtime)
    assert newest.parent.name != final_run  # mtime ordering now favours history

    result = pinned_result(exp, root / "FINAL_MANIFEST.json", root)
    assert result["run_id"] == final_run


def test_missing_manifest_fails(tmp_path):
    with pytest.raises(EvidenceResolutionError, match="manifest missing"):
        pinned_result("e2", tmp_path / "FINAL_MANIFEST.json", tmp_path)


def test_missing_pinned_evidence_fails(tmp_path):
    root = _copy_evidence(tmp_path, "e2", [])
    with pytest.raises(EvidenceResolutionError, match="pinned evidence missing"):
        pinned_result("e2", root / "FINAL_MANIFEST.json", root)


@pytest.mark.parametrize("field, bad_value, message", [
    ("run_id", "19700101T000000Z", "run_id"),
    ("experiment_id", "e9", "experiment_id"),
])
def test_result_disagreeing_with_manifest_fails(tmp_path, field, bad_value, message):
    final_run = load_manifest()["e2_run_id"]
    root = _copy_evidence(tmp_path, "e2", [final_run])
    path = root / "e2" / final_run / "result.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = bad_value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EvidenceResolutionError, match=message):
        pinned_result("e2", root / "FINAL_MANIFEST.json", root)
