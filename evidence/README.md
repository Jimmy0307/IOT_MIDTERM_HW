# Evidence Directory Guide

`evidence/FINAL_MANIFEST.json` identifies the authoritative final run for each
experiment. `docs/EVIDENCE_INDEX.md` maps the frozen specification's evidence
items to files and scenario IDs.

## Final runs

- `e1/20261030T193936Z`
- `e2/20261030T193709Z`
- `e3/20261030T193723Z`

Only these three runs support the report's PASS claims.

## Historical, non-final runs

All other timestamped directories are historical attempts retained for
provenance. They are **not** final results and must not be used to support the
report's PASS claims:

- `e1/20261028T200057Z`, `e1/20261028T200341Z`, `e1/20261028T200436Z`,
  `e1/20261028T200912Z`: development attempts
- `e1/20261028T202401Z`: previous final run, superseded (no raw PCAPs, no E1-03)
- `e1/20261030T193736Z`: FAIL (`PCAP_EVIDENCE_AVAILABLE=NO`; attacker-side
  baseline capture was empty), superseded by `e1/20261030T193936Z`
- `e2/20261028T195126Z`, `e2/20261028T202400Z`: previous runs
- `e3/20261028T195735Z`, `e3/20261028T202401Z`: previous runs

## Raw captures

Raw `.pcap` files are gitignored. The final E1 run's raw captures
(`E1-03_baseline.pcap`, `E1-04_mitm_http.pcap`, `E1-06_mitm_https.pcap`) ship
in the submission ZIP and are pinned by SHA-256 in the manifest.
