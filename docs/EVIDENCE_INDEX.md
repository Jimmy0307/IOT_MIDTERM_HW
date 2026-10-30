# Final Evidence Index

This is an additive navigation and provenance aid for Assignment #3 V2.2. It
does not replace the frozen specification, the machine-readable results, or the
final manifest (`evidence/FINAL_MANIFEST.json`).

## Authoritative final run IDs

| Experiment | Final run | Source of verdict | Verdict |
|---|---|---|---|
| E1 ARP/MITM | `20261030T193936Z` | `evidence/e1/20261030T193936Z/result.json` | PASS |
| E2 Replay | `20261030T193709Z` | `evidence/e2/20261030T193709Z/result.json` | PASS |
| E3 SQL Injection | `20261030T193723Z` | `evidence/e3/20261030T193723Z/result.json` | PASS |

Source commit `b88c364`; evidence-freeze commit `62d8909`; test suite
`20 passed, 0 failed, 0 skipped`. Every final `result.json` records
`evidence_location` as the repository-relative path `evidence/<exp>/<run_id>`.

## Final vs historical runs

Only the three runs above are final. All other timestamped directories are
historical, non-final, and must not be used to support report claims:

| Experiment | Historical run(s) | Note |
|---|---|---|
| E1 | `20261028T200057Z`, `20261028T200341Z`, `20261028T200436Z`, `20261028T200912Z` | development attempts |
| E1 | `20261028T202401Z` | previous final run; predates raw-PCAP preservation and E1-03 capture |
| E1 | `20261030T193736Z` | FAIL: `PCAP_EVIDENCE_AVAILABLE=NO` because the baseline was captured on the attacker, which sees no victim/gateway unicast before poisoning; superseded by `20261030T193936Z` |
| E2 | `20261028T195126Z`, `20261028T202400Z` | previous runs (absolute `evidence_location`) |
| E3 | `20261028T195735Z`, `20261028T202401Z` | previous runs (absolute `evidence_location`) |

## E1 ARP/MITM mapping (run `20261030T193936Z`)

All files are under `evidence/e1/20261030T193936Z/`.

| Frozen evidence item | Raw artifact | Text rendering / supporting files | Result scenario |
|---|---|---|---|
| E1-01 Baseline ARP Table | n/a | `E1-01_baseline_arp.txt` | `E1-FEASIBILITY-GATE` (`ARP_TABLE_VISIBLE`) |
| E1-02 Poisoned ARP Table | n/a | `E1-02_poisoned_arp.txt` | `E1-MITM-PATH` |
| E1-03 Baseline PCAP | `E1-03_baseline.pcap` (1,387 B; captured on `e1_victim` before the attack) | `E1-03_baseline_pcap.txt`, `E1-03_baseline_http_response.txt` | `E1-FEASIBILITY-GATE` (`PCAP_EVIDENCE_AVAILABLE`) |
| E1-04 MITM PCAP | `E1-04_mitm_http.pcap` (2,622 B; captured on `e1_attacker`; contains the demo token) | `E1-04_mitm_http_pcap.txt` | `E1-FEASIBILITY-GATE`, `E1-HTTP-PAYLOAD-EXPOSED` |
| E1-05 HTTP Payload Observation | `E1-04_mitm_http.pcap` | `E1-05_mitm_http_response.txt`, `E1-04_mitm_http_pcap.txt` | `E1-HTTP-PAYLOAD-EXPOSED` |
| E1-06 HTTPS Payload Observation | `E1-06_mitm_https.pcap` (12,312 B; captured on `e1_attacker`; token absent) | `E1-06_mitm_https_pcap.txt`, `E1-06_https_response_validated.txt` | `E1-HTTPS-PAYLOAD-PROTECTED` |
| E1-07 Certificate Validation | n/a | `E1-07_cert_validation.txt` (trusted CA: curl exit 0; untrusted: HTTP code `000`, curl exit 60 = TLS handshake rejected, not an HTTP response) | `E1-TLS-CERT-VALIDATION` |
| E1-08 Regression | n/a | `E1-08_restored_arp.txt`, `E1-08_regression_http_response.txt`, `E1-08_regression_https_response.txt` | `E1-REGRESSION` |
| Feasibility gate (spec §2.1) | n/a | `feasibility_gate.json` (6/6 true) | `E1-FEASIBILITY-GATE` |
| DoS contrast (spec §7.2) | n/a | `E1-DOS_http_response.txt` (empty = disruption; not MITM) | `E1-DOS-WITHOUT-FORWARDING` |

The SHA-256 of each raw PCAP is recorded in `evidence/FINAL_MANIFEST.json`.
Raw `.pcap` files are gitignored and ship in the submission ZIP.

## E2 Replay mapping (run `20261030T193709Z`)

All E2 PASS gates are in `evidence/e2/20261030T193709Z/result.json`:

| Frozen gate | Scenario ID | Supporting file |
|---|---|---|
| Vulnerable exact replay accepted | `E2-VULN-EXACT-REPLAY` | `result.json` |
| First protected request accepted | `E2-PROT-FIRST-ACCEPT` | `audit_log.json` (ACCEPT) |
| Exact replay rejected | `E2-PROT-EXACT-REPLAY` | `audit_log.json` (REJECT, nonce consumed) |
| Modified nonce rejected | `E2-PROT-MODIFIED-NONCE` | `audit_log.json` (REJECT, signature mismatch) |
| Modified timestamp rejected | `E2-PROT-MODIFIED-TIMESTAMP` | `audit_log.json` (REJECT, signature mismatch) |
| Modified body rejected | `E2-PROT-MODIFIED-BODY` | `audit_log.json` (REJECT, signature mismatch) |
| Action count unchanged | `E2-PROT-ACTION-STATE` | `device_history.json` (`action_count` = 1) |
| Audit log created | `E2-PROT-AUDIT-LOG` | `audit_log.json` (5 events) |

## E3 SQL Injection mapping (run `20261030T193723Z`)

The E3 runner consolidates gate results in
`evidence/e3/20261030T193723Z/result.json` rather than emitting eleven
separate files. The mapping below makes that consolidation explicit:

| Frozen evidence item | Source |
|---|---|
| E3-01 User Input | `E3-01_user_input.txt` |
| E3-02 Generated SQL / DB Query Log | `E3-02_generated_sql.txt` |
| E3-03 HTTP Response | `result.json` scenarios `E3-VULN-SEMANTICS` and `E3-FIXED-PARAMETERIZED` (the runner uses direct DB calls rather than an HTTP server) |
| E3-04 Returned Row Count | `result.json` details for `E3-VULN-SEMANTICS` (1 vs 4 rows) and `E3-FIXED-PARAMETERIZED` (1 vs 0 rows) |
| E3-05 Parameterized Query Result | `result.json` scenario `E3-FIXED-PARAMETERIZED` |
| E3-06 DB State | `result.json` scenario `E3-DB-STATE` (before = after = 4) |
| E3-07 Normal Regression | `result.json` scenario `E3-REGRESSION` |
| E3-08 Allowed-table SELECT | `result.json` scenario `E3-CONTAIN-ALLOWED-SELECT` |
| E3-09 Sensitive-table SELECT Denied | `result.json` scenario `E3-CONTAIN-SENSITIVE-READ` |
| E3-10 Unauthorized UPDATE Denied | `result.json` scenario `E3-CONTAIN-UNAUTH-UPDATE` |
| E3-11 Unauthorized DROP Denied | `result.json` scenario `E3-CONTAIN-UNAUTH-DROP` |

## Path portability note

Historical `result.json` files contain the original Windows absolute evidence
path in `evidence_location`; they are preserved unchanged for provenance. The
final runs use the repository-relative form `evidence/<experiment>/<run_id>`.
