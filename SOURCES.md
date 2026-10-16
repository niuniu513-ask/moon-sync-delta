# Sources, ecosystem relationship and finite search

Rechecked 2026-10-16 (Asia/Shanghai). This is an extension of an existing MoonBit delta ecosystem component, not an assertion of no functional overlap or guaranteed contest acceptance.

## Direct reuse

- `yangxixi00/moon_vcdiff@0.1.0`, Apache-2.0, <https://github.com/yangxixi00/moon-vcdiff>. Actual declared dependency. The extension calls `default_code_table`, `encode_unsigned_integer`, `inspect`, `DecodeLimits::new` and `decode`; examples/tests also call upstream encode/validate APIs. No upstream source is vendored or modified. Its dependency is `moonbitlang/x@0.5.1`, Apache-2.0. Published archive SHA-256: `52550bef3f426bde115ca8fee2ddb2b60ef9058f252e79c811d0d41d8d880c18`.
- `gmlewis/sha256@0.18.0`, Apache-2.0, <https://github.com/gmlewis/moonbit-sha256>; transitive `gmlewis/base64@0.16.13`, Apache-2.0. Upstream SHA-256 identifies Go/BSD-style lineage; preserve those notices when redistributing bundled dependency code.
- Dependency packages retain licenses under ignored `.mooncakes/`. Redistribution of binaries or bundled source must retain applicable Apache-2.0 licenses, attribution and any NOTICE files; the MIT license only covers this project's own work.

## Algorithm and specification references

- Andrew Tridgell and Paul Mackerras, *The rsync algorithm*, <https://rsync.samba.org/tech_report/>. Reference for fixed receiver block signatures and rolling matching. No rsync/librsync source copied; no rsync command compatibility.
- RFC 3284, <https://www.rfc-editor.org/rfc/rfc3284>, specification reference for the generated VCDIFF profile. The implementation uses the MoonBit dependency's public code-table/integer APIs and its decoder.
- Own matching/indexing, MSIG/MSDL/MSVF framing, signature-to-VCDIFF translation, adapters, examples and tests were authored with AI assistance. Test data is synthetic; no third-party corpora, adoption or performance claims.
- Node.js is only a filesystem host; Python standard library supplies independent oracles. No network protocol is implemented.

## Purpose-level overlap

| Existing project | Relationship after correction |
|---|---|
| `yangxixi00/moon_vcdiff@0.1.0` | Same binary-delta field. Now a real dependency, extended with signature-only sender generation; not a competing general decoder. |
| `bzhangui/moonrestore@0.1.0` | Existing verifiable incremental backup/CAS/snapshot/restore application. Not integrated. Backup project claims withdrawn; no backup directory or snapshot feature here. Binary update use cases may still intersect. |
| `cn-ybm/MoonHashKit@0.3.0` | Earlier inspected CDC, manifests, fingerprints and missing-block APIs. Adjacent deduplication purpose; not a claimed dependency. |
| `xgzh1111/moonchunk@0.1.0` | Earlier inspected CDC/manifests/Merkle/chunk-store/restore features. Adjacent purpose; not a claimed dependency. |

The initial review explicitly rejected the standalone delta/backup positioning. Different algorithms or API arguments did not establish eligibility. The new contribution is concrete interoperability and a new generation condition on an actual existing dependency. Upstream acceptance, collaboration or an upstream PR is not claimed.

## Search evidence and limits

Fresh registry endpoint <https://mooncakes.io/api/v0/modules> returned 3,038 metadata records. On 2026-10-16 searched names/descriptions/keywords for rsync, vcdiff, delta-sync/deltasync, rolling checksum, remote sync and librsync: the named VCDIFF package was the hit. Also checked the named moonrestore metadata and read the published VCDIFF API/source/license. This does not exclude related functionality under other names.

Snapshot SHA-256 `0d0e8d320e277eb4894582f5f65fd642e3b77fa726d9f9ff7931ff276ae9e48c`; local full snapshot is outside the repository under contest-submission. Public evidence: `docs/research/review-20261016.json`. Older 2026-10-11 searches are retained as historical evidence in `docs/research/search-evidence.json`, not treated as current or proof of eligibility. No fresh exhaustive GitHub code search was performed; unindexed/private/unpublished competition work cannot be ruled out.

## Review and rule provenance

Rule interpretation uses the user's supplied charter and the supplied rejection email. The email gives this project's correction opportunity before October 31; old dates in pasted charter text are not silently replaced for every entrant. Current extension remains subject to organizer review. Project proposal must be personally rewritten/confirmed by the entrant under the charter's manual-writing requirement.
