# Submission Provenance Note

This note explains the commit roles behind `evidence/FINAL_MANIFEST.json`. It
does not change the frozen V2.2 architecture, threat model, experiment scope,
security controls, or acceptance criteria.

## Commit roles

| Role | Commit |
|---|---|
| Source commit that produced the final runs | `b88c3649e9fccb592a20cf5e3f58c1271c39a233` |
| Evidence-freeze commit (final run directories) | `62d89093854e705e8e2ce11e1fadcd7068ec4c98` |
| Publication commit (manifest, index, report, DOCX/PDF) | the commit that adds this note; it follows `62d8909` |

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

Raw `.pcap` files are excluded by `.gitignore`. They are included in the
submission ZIP and pinned by SHA-256 in the manifest.

## Superseded commits

The previous final runs (E1 `20261028T202401Z`, E2 `20261028T202400Z`,
E3 `20261028T202401Z`) were produced from source commit `b9d342d`, frozen in
`59385f9`, and published in `f7a0bac`. They remain in the tree as historical,
non-final evidence.

## Test-count breakdown

```text
20 passed, 0 failed, 0 skipped
```

The suite is composed of 10 E2 unit/security tests, 7 E3 database
security/regression tests, and 3 consolidated acceptance-gate tests. The
acceptance-gate tests read the latest `result.json` per experiment, which are
the final runs above.

## Submission rule

The report may cite only the final run IDs above. Historical run directories
remain in the tree for provenance and are not final evidence.
