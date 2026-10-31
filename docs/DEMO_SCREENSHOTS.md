# Assignment #3 V2.2 — Fresh Demo PowerShell Screenshots

Baseline commit: `d314a283ffef79050dc5a358003caaafa13a710c`

Fresh demo runs:
- E1: `20261031T061521Z`
- E2: `20261031T061513Z`
- E3: `20261031T070851Z`
- Full test suite: `27 passed, 0 failed, 0 skipped`

> These screenshots are fresh demonstration evidence produced from the same fixed commit. They supplement, but do not replace, the previously frozen submission evidence. Original PNG binaries are backed up under the Google Drive submission folder; GitHub keeps the index, hashes, and verified backup links.

## 1. Git version / clean tree

[Open 01_git_version_clean_tree.png](https://drive.google.com/file/d/1onp55_uUfGX4mP7WIwA3SV0WbIo_ZFk0/view?usp=drivesdk)

## 2. Runtime environment

[Open 02_runtime_environment.png](https://drive.google.com/file/d/1ZHaiFKdJ82Xyxjnka-OWcg8QCTpB1QbL/view?usp=drivesdk)

## 3. E2 Replay Attack

[Open 03_e2_replay_demo.png](https://drive.google.com/file/d/1032c3CTUX-ZZECIBpVerWqMKH8M95Gt_/view?usp=drivesdk)

Key result: vulnerable replay changes `action_count` from 1 to 2; protected replay is rejected and the state remains 1.

## 4. E3 and E1 execution

[Open 04_e3_and_e1_execution.png](https://drive.google.com/file/d/1xQj6OOdcuHiAH-nvYIQiiQbxi-ekY6bP/view?usp=drivesdk)

E3 demonstrates `1 row -> 4 rows -> 0 rows` and least-privilege denials. E1 runner shows feasibility, MITM, HTTP/HTTPS, TLS certificate validation, and regression PASS.

## 5. E1 ARP / HTTP / HTTPS / TLS

[Open 05_e1_arp_http_https_tls.png](https://drive.google.com/file/d/1ReOt-DYKhiMhSHpEThE2OX034dhdEOf8/view?usp=drivesdk)

Key result: Gateway IP keeps the same IP but changes MAC under ARP spoofing; HTTP token occurrences = 2, HTTPS token occurrences = 0; trusted CA succeeds and untrusted CA is rejected.

## 6. Recovery and complete tests

[Open 06_recovery_tests_summary.png](https://drive.google.com/file/d/15hbD7nfZCOG8DUlkBZbKN5fcvGV10lkq/view?usp=drivesdk)

Key result: ARP is restored, normal HTTP/HTTPS service works again, and the full suite reports 27 passed.

## 7. Final demo summary

[Open 07_final_demo_summary.png](https://drive.google.com/file/d/1fno16Om6Ug7ocp5lMfn_4PhDkKS_HHpC/view?usp=drivesdk)

All three experiments are reproduced successfully from the fixed repository baseline.

## 8. PostgreSQL + E3 clean rerun

[Open 08_postgresql_e3_clean.png](https://drive.google.com/file/d/1C0HBO_squ-keSFfnxSjs7l5hUz4sK7dW/view?usp=drivesdk)

Key result: the previous PostgreSQL container/network were removed, PostgreSQL was recreated cleanly, health reached `healthy`, and E3 again passed with `1 -> 4 -> 0`, least-privilege denials, DB state `4 -> 4`, and regression PASS.

## Report backups

- [zh-TW DOCX v2](https://drive.google.com/file/d/1tTUy0V1WAEd-rmoZVCoQdx8DP75IsvD8/view?usp=drivesdk)
- [zh-TW PDF v2](https://drive.google.com/file/d/12nsAcLKUmIDzMTFZRDpcHqNCG2-aqvDO/view?usp=drivesdk)
