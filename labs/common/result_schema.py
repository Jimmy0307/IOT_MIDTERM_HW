"""Unified machine-readable result schema (V2.2 spec section 16 / 31).

Every experiment scenario emits a ``ScenarioResult`` serialized to JSON so that
report conclusions can always be traced back to concrete evidence.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    """Allowed verdict values (spec section 31)."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp (second precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class ScenarioResult:
    """One row of the unified result schema.

    Immutable: a new object is produced per scenario rather than mutating a
    shared record (coding-style: immutability).
    """

    experiment_id: str
    scenario_id: str
    attacker_model: str
    trust_boundary: str
    expected_result: str
    actual_result: str
    security_control: str
    evidence_location: str
    verdict: Verdict
    timestamp: str = field(default_factory=utc_now_iso)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass(frozen=True)
class ExperimentReport:
    """Aggregated results for a whole experiment run (e1/e2/e3)."""

    experiment_id: str
    run_id: str
    scenarios: tuple[ScenarioResult, ...]

    @property
    def verdict(self) -> Verdict:
        verdicts = {s.verdict for s in self.scenarios}
        if not verdicts:
            return Verdict.FAIL
        if verdicts == {Verdict.PASS}:
            return Verdict.PASS
        if Verdict.FAIL in verdicts:
            return Verdict.FAIL
        return Verdict.PARTIAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "run_id": self.run_id,
            "generated_at": utc_now_iso(),
            "verdict": self.verdict.value,
            "scenario_count": len(self.scenarios),
            "scenarios": [s.to_dict() for s in self.scenarios],
        }

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path
