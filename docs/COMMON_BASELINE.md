# P1 — Common Baseline

Canonical spec: [`ASSIGNMENT3_IOT_SECURITY_LAB_V2_2_FROZEN.md`](./ASSIGNMENT3_IOT_SECURITY_LAB_V2_2_FROZEN.md)

This document fixes the shared architecture, trust boundaries, threat model and
result conventions used by all three experiments (spec sections 4–6, 31).

## Architecture (spec section 4)

```
External/Lab Client → Frontend → HTTPS → Nginx (TLS termination)
    → FastAPI Backend
        ├── Data Path    → PostgreSQL
        └── Command Path → IoT Service → Device Simulator
```

The database is **not** on the mandatory path of every IoT command. The command
path (E2) reaches the device through the IoT Service, independent of PostgreSQL.

### How this maps to the runnable labs

| Layer | Canonical component | Runnable artifact in this repo |
|---|---|---|
| Command path / message auth | FastAPI backend | `labs/e2_replay/server.py` (FastAPI app, raw-body HMAC) |
| Data path / DB authorization | FastAPI + PostgreSQL | `labs/e3_sqli/*` + `docker-compose.yml` (PostgreSQL + least-priv role) |
| Network / transport | Nginx TLS + L2 network | `labs/e1_arp/*` (isolated Docker L2 + TLS gateway) |

E2 is exercised in-process via FastAPI `TestClient` for deterministic evidence;
the same application logic is the canonical FastAPI backend.

## Trust Boundaries (spec section 5)

| ID | Boundary | Experiment |
|---|---|---|
| TB-A | Network → Reverse Proxy / TLS | E1 (network trust) |
| TB-B | Reverse Proxy → Backend | E2 (message trust) |
| TB-C | Backend → Database | E3 (code/data boundary + DB authz) |
| TB-D | Application / IoT Service → Device | E2 (freshness) |

## Unified Threat Model (spec section 6)

| Exp | Attacker position | Capability | Explicit assumption |
|---|---|---|---|
| E1 | same L2 network | ARP manipulation, interception | HTTP observable; correct TLS protects payload |
| E2 | holds one captured legitimate request | replay / modify captured request | request from log leak / client compromise / post-TLS internal; **TLS not broken** |
| E3 | can reach Backend API | supply malicious input | request already reached the Application layer |

The three attackers are distinct roles, not one omnipotent adversary.

## Result schema (spec section 31)

Every scenario emits a row (`labs/common/result_schema.py`):
`experiment_id, scenario_id, timestamp, attacker_model, trust_boundary,
expected_result, actual_result, security_control, evidence_location, verdict`
with `verdict ∈ {PASS, FAIL, PARTIAL}`. Evidence is written under
`evidence/<exp>/<run_id>/` (spec section 17).

## Experiment lifecycle (spec section 2 / 30)

```
prepare → baseline → controlled test → evidence → defense → re-test
       → regression → residual risk → verdict
```
Any PASS without supporting evidence is treated as FAIL (spec section 2).
