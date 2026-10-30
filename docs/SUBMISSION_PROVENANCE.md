# Submission Provenance Note

This note explains the commit roles behind `evidence/FINAL_MANIFEST.json`. It
does not change the frozen V2.2 architecture, threat model, experiment scope,
security controls, or acceptance criteria.

## Commit roles

| Role | Commit |
|---|---|
| `SOURCE_COMMIT`: code that produced the final runs | `b88c3649e9fccb592a20cf5e3f58c1271c39a233` |
| `EVIDENCE_FREEZE_COMMIT`: final run directories committed | `62d89093854e705e8e2ce11e1fadcd7068ec4c98` |
| `PREVIOUS_PUBLICATION_COMMIT`: manifest, index, report, DOCX/PDF first published | `a9a54d7491222c6ac62e27bd5176e9586faacfd7` |
| `FINAL_CLOSURE_COMMIT`: closure pass (manifest-pinned acceptance gates, report wording, E3 boundary, this note) | the commit that adds this revision; its SHA is recorded outside the repository in `HW_MID_CYBERIOT_Assignment3_V2.2_submission_20261031.sha256.txt` |

These roles are distinct. The source commit is **not** the final package
commit: the evidence-freeze, publication, and closure commits change only
documentation, tests, and the manifest, never runner or lab code. A commit
cannot contain its own SHA, so the closure SHA is recorded in the sidecar file
rather than in the manifest.

The manifest's `git_commit` field equals `source_commit` and is kept for
compatibility with the previous manifest format.

The source commit adds repository-relative `evidence_location` paths, raw PCAP
preservation for E1-03/E1-04/E1-06, and the E1-08 HTTP/TLS response files. It
moves the E1-03 baseline capture to the victim. Before ARP poisoning, the
Docker bridge does not switch victim/gateway unicast to the attacker, so an
attacker-side baseline capture is empty by design. Run `20261030T193736Z`
recorded that empty capture as `PCAP_EVIDENCE_AVAILABLE=NO` and is retained
as a historical FAIL.

## Final evidence runs

- E1: `20261030T193936Z` (feasibility gate 6/6 true)
- E2: `20261030T193709Z`
- E3: `20261030T193723Z`

The closure pass did not rerun any experiment. The final runs, their
`result.json` files, and the raw PCAP bytes are unchanged since
`62d89093854e705e8e2ce11e1fadcd7068ec4c98`.

Raw `.pcap` files are excluded by `.gitignore`. They are included in the
submission ZIP and pinned by byte size and SHA-256 in the manifest.

## Superseded commits

The previous final runs (E1 `20261028T202401Z`, E2 `20261028T202400Z`,
E3 `20261028T202401Z`) were produced from source commit `b9d342d`, frozen in
`59385f9`, and published in `f7a0bac`. They are historical/superseded and
remain in the tree only for provenance.

## Test counts

At the evidence freeze (`62d8909`):

```text
20 passed, 0 failed, 0 skipped
```

After the closure pass:

```text
27 passed, 0 failed, 0 skipped
```

The suite is composed of 10 E2 unit/security tests, 7 E3 database
security/regression tests (these need the lab PostgreSQL:
`docker compose up -d postgres`), and 10 acceptance-gate tests. The
acceptance-gate tests are 3 gate tests plus 7 tests that prove pinning
behavior. The gate tests resolve exactly
`evidence/<exp>/<manifest run_id>/result.json`. They never select a run by file
timestamp and fail hard on a missing manifest, missing pinned evidence, or a
`run_id` / `experiment_id` mismatch.

## Submission rule

The report may cite only the final run IDs above. Historical run directories
remain in the tree for provenance and are not final evidence.
