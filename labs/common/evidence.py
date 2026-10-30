"""Evidence directory + run-id helpers (V2.2 spec section 17).

Layout::

    evidence/<exp>/<run_id>/
        metadata.json
        result.json
        <logs, captures, db state, test output>
"""

from __future__ import annotations

import json
import os
import platform
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Project root = two levels up from this file (labs/common/evidence.py -> repo root)
REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = REPO_ROOT / "evidence"


def new_run_id() -> str:
    """Timestamp-based run id, e.g. ``20261029T041530Z``."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True)
class EvidenceRun:
    """A single experiment run's evidence directory."""

    experiment_id: str
    run_id: str
    base: Path

    @property
    def dir(self) -> Path:
        return self.base

    def path(self, name: str) -> Path:
        return self.base / name

    def write_text(self, name: str, content: str) -> Path:
        p = self.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def write_json(self, name: str, obj: Any) -> Path:
        return self.write_text(name, json.dumps(obj, indent=2, default=str))


def start_run(experiment_id: str, run_id: str | None = None) -> EvidenceRun:
    """Create ``evidence/<exp>/<run_id>/`` and seed ``metadata.json``."""
    rid = run_id or new_run_id()
    base = EVIDENCE_ROOT / experiment_id / rid
    base.mkdir(parents=True, exist_ok=True)
    run = EvidenceRun(experiment_id=experiment_id, run_id=rid, base=base)
    run.write_json(
        "metadata.json",
        {
            "experiment_id": experiment_id,
            "run_id": rid,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "scope": "LAB / LOCAL ONLY - isolated project-owned components",
            "pid": os.getpid(),
        },
    )
    return run


def relative_evidence_path(path: Path) -> str:
    """Return a portable, repository-relative evidence path."""
    return path.relative_to(REPO_ROOT).as_posix()
