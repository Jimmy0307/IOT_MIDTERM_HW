# Assignment #3 — IoT Security Lab (V2.2 FROZEN)

Controlled, closed educational lab implementing the frozen V2.2 specification:
[`docs/ASSIGNMENT3_IOT_SECURITY_LAB_V2_2_FROZEN.md`](docs/ASSIGNMENT3_IOT_SECURITY_LAB_V2_2_FROZEN.md)
(the single canonical spec).

| ID | Experiment | Trust boundary | What it proves |
|----|------------|----------------|----------------|
| **E1** | ARP Spoofing / MITM | TB-A network | plaintext interception vs TLS payload protection |
| **E2** | Replay Attack | TB-B / TB-D message | HMAC(raw body)+nonce+timestamp stop replay |
| **E3** | SQL Injection | TB-C code/data | parameterized query (PREVENT) + least privilege (CONTAIN) |

**Primary = E1.** Fallback order (spec §3/§33): E1 feasibility FAIL → E3 primary → then E2.

## Scope / safety boundary (spec §0)

Everything runs against **localhost / a dedicated private Docker network /
project-owned containers only**. No public targets, no real credentials, no
destructive operations, no arbitrary target input (E1 targets are fixed by the
lab topology). All lab credentials are marked `DEMO / LOCAL ONLY`.

## Prerequisites

- Python 3.11+ (developed on 3.14)
- Docker Desktop (E1 network lab, E3 PostgreSQL)

## Quick start

```bash
pip install -r requirements.txt          # or: make setup
cp .env.example .env                      # DEMO/LOCAL values

# E2 — Replay (in-process, no external services)
python runners/run_e2.py

# E3 — SQL Injection (needs lab PostgreSQL)
docker compose up -d postgres             # or: make db-up
python runners/run_e3.py

# E1 — ARP/MITM (isolated Docker L2 network; builds its own image)
python runners/run_e1.py                  # add --down to tear the lab down after

# Everything + consolidated verdicts
python runners/run_all.py

# Tests (unit / integration / security / acceptance gates)
python -m pytest -q
```

## Layout

```
docs/      canonical spec, common baseline, final report
labs/
  common/      result schema + evidence helpers
  e2_replay/   canonical request, HMAC, nonce cache, device, FastAPI server, client
  e3_sqli/     db + seed (least-priv role), vulnerable (raw SQL), safe (parameterized)
  e1_arp/      gateway TLS server, ARP poisoner, Docker L2 compose
runners/   run_e1.py run_e2.py run_e3.py run_all.py  (prepare→…→verdict, spec §15)
tests/     unit / security / acceptance-gate suites
evidence/  evidence/<exp>/<run_id>/ : metadata.json, result.json, logs, captures
```

## Evidence & verdicts

Each runner writes `evidence/<exp>/<run_id>/result.json` using the unified schema
(spec §31) with a `PASS/FAIL/PARTIAL` verdict per scenario. A PASS without
evidence is treated as FAIL (spec §2). The acceptance-gate tests
(`tests/test_acceptance_gates.py`) re-validate the latest evidence against the
V2.2 Final Acceptance Gates (spec §35).

For the submission package, use [`docs/EVIDENCE_INDEX.md`](docs/EVIDENCE_INDEX.md)
to map each frozen evidence item to its file or result scenario, and
[`docs/SUBMISSION_PROVENANCE.md`](docs/SUBMISSION_PROVENANCE.md) for the roles
of the source, evidence-freeze, and publication commits. Historical run
directories are retained for provenance; only the run IDs in
`evidence/FINAL_MANIFEST.json` are authoritative for the final report.

## Defense-in-depth labeling (spec §14/§29)

`[I]` = implemented + verified in this lab; `[C]` = conceptual discussion only.
See the Defense-in-Depth matrix in [`docs/final_report.md`](docs/final_report.md).
This lab implements **Prevent + partial Detect + Contain**; Recover is conceptual.
