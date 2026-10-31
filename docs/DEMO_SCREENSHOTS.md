# Assignment #3 V2.2 — Fresh Demo PowerShell Screenshots

Baseline commit: `d314a283ffef79050dc5a358003caaafa13a710c`

Fresh demo runs:
- E1: `20261031T061521Z`
- E2: `20261031T061513Z`
- E3: `20261031T070851Z`
- Full test suite: `27 passed, 0 failed, 0 skipped`

> These screenshots are fresh demonstration evidence produced from the same fixed commit. They supplement, but do not replace, the previously frozen submission evidence.

## 1. Git version / clean tree

![Git version and clean tree](demo_screenshots/01_git_version_clean_tree.png)

## 2. Runtime environment

![Python and Docker runtime](demo_screenshots/02_runtime_environment.png)

## 3. E2 Replay Attack

![E2 replay demonstration](demo_screenshots/03_e2_replay_demo.png)

Key result: vulnerable replay changes `action_count` from 1 to 2; protected replay is rejected and the state remains 1.

## 4. E3 and E1 execution

![E3 and E1 execution](demo_screenshots/04_e3_and_e1_execution.png)

E3 demonstrates `1 row -> 4 rows -> 0 rows` and least-privilege denials. E1 runner shows feasibility, MITM, HTTP/HTTPS, TLS certificate validation, and regression PASS.

## 5. E1 ARP / HTTP / HTTPS / TLS

![ARP HTTP HTTPS TLS](demo_screenshots/05_e1_arp_http_https_tls.png)

Key result: Gateway IP keeps the same IP but changes MAC under ARP spoofing; HTTP token occurrences = 2, HTTPS token occurrences = 0; trusted CA succeeds and untrusted CA is rejected.

## 6. Recovery and complete tests

![Recovery and tests](demo_screenshots/06_recovery_tests_summary.png)

Key result: ARP is restored, normal HTTP/HTTPS service works again, and the full suite reports 27 passed.

## 7. Final demo summary

![Final demo summary](demo_screenshots/07_final_demo_summary.png)

All three experiments are reproduced successfully from the fixed repository baseline.

## 8. PostgreSQL + E3 clean rerun

![PostgreSQL + E3 clean rerun](demo_screenshots/08_postgresql_e3_clean.png)

Key result: the previous PostgreSQL container/network were removed, PostgreSQL was recreated cleanly, health reached `healthy`, and E3 again passed with `1 -> 4 -> 0`, least-privilege denials, DB state `4 -> 4`, and regression PASS.
