"""Run every experiment runner in the frozen execution order (spec section 33).

Order: E2 -> E3 -> E1 (E1 last because it is the heaviest / highest env risk;
its own P0 feasibility gate runs first inside run_e1). Prints a consolidated
verdict table. Use ``--down`` to tear down the E1 lab afterwards.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUNNERS = ["run_e2.py", "run_e3.py", "run_e1.py"]


def main() -> int:
    overall = 0
    for r in RUNNERS:
        print(f"\n########## {r} ##########", flush=True)
        extra = ["--down"] if (r == "run_e1.py" and "--down" in sys.argv) else []
        rc = subprocess.run(
            [sys.executable, str(REPO / "runners" / r), *extra]
        ).returncode
        overall = overall or rc
    print(f"\n=== run_all finished | overall_exit={overall} ===")
    return overall


if __name__ == "__main__":
    raise SystemExit(main())
