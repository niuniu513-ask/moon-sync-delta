# Sources, provenance and duplicate-check scope

Checked on 2026-10-11 (Asia/Shanghai). The user's supplied contest charter is the rule source.
This file describes a finite search, not proof of worldwide novelty or guaranteed contest acceptance.

## Algorithm and implementation

- Andrew Tridgell and Paul Mackerras, *The rsync algorithm*, technical report:
  <https://rsync.samba.org/tech_report/>. The receiver-signature / rolling-window / strong-checksum
  architecture follows this established algorithm. The unsigned-byte weak checksum is specified
  explicitly in `docs/WIRE_FORMAT.md`; strong checksums are SHA-256, not the historic MD4 choice.
- The project's matching, framing, bounds checking, statistics, file host adapter, examples and tests
  were written for this project with AI assistance. No source code from rsync, librsync, MoonHashKit,
  MoonChunk, MoonRestore or moon_vcdiff was copied.
- The `MSIG` / `MSDL` version-1 frame is a project-specific representation. Neither rsync command
  compatibility nor librsync/VCDIFF wire compatibility is implemented or claimed.

## Existing dependency reused

- `gmlewis/sha256@0.18.0`, Apache-2.0:
  <https://github.com/gmlewis/moonbit-sha256>. This package exposes `Digest::new/write/check_sum`.
  Its documentation identifies a Go SHA-256 implementation lineage and BSD-style notice.
- Its registry dependency is `gmlewis/base64@0.16.13`, Apache-2.0.
- Dependency source and licenses are retained by the package manager under ignored `.mooncakes/`.
  Project SHA-256 code was not copied or reimplemented. A binary/source redistribution that includes
  third-party dependency code must retain the dependency license/notice obligations.
- Node.js is used only by optional `cmd/files`. Python's standard library is used by an independent
  validation script. No external third-party test data is distributed.
- Test files and examples use authored or seeded synthetic bytes. They are controlled experiments,
  not real backup workloads, external adoption evidence or throughput benchmarks.

## Mooncakes search

Endpoint: <https://mooncakes.io/api/v0/modules>. Retrieved 2,938 module metadata records.
Names, descriptions and keywords were searched, with terms including `rsync`, `librsync`,
`rolling checksum`, `rolling hash`, `block signature`, `fingerprint`, `chunk`, `backup`,
`synchronization`, `content-defined`, `delta` and `vcdiff` (including common separator variants).

Raw index SHA-256:
`6073ac935483bce5ae6842ff4f41955690bae53420c93f68817c6267224cee19`.
The raw index and downloaded reference archives are retained outside the project, in the local
`D:\moonbit\contest-submission\moon-sync-delta-research` directory. Public metadata summary:
[docs/research/search-evidence.json](docs/research/search-evidence.json).

## Nearby projects inspected

| Project | Evidence read | Relationship |
|---|---|---|
| `cn-ybm/MoonHashKit@0.3.0` | README and published package's public interface | CDC, manifests, weak fingerprints, chunk matching and missing-block plans. Its verified-match and missing-block APIs require original byte arrays. This project does not implement CDC; its sender accepts only receiver signatures. |
| `xgzh1111/moonchunk@0.1.0` | Published package README | CDC, manifests, Merkle proofs, chunk stores and restore. Similar synchronization use cases exist. Its documented pipeline is content-addressed chunk reuse; this project scans sender windows against fixed receiver block signatures. |
| `bzhangui/moonrestore@0.1.0` | Registry metadata and published README | An existing incremental-backup application. This project provides a lower-level remote-signature algorithm, not another backup application. Its README has encoding problems, so only legible metadata/architecture evidence is relied upon. |
| `yangxixi00/moon_vcdiff@0.1.0` | Published public interface | RFC 3284 encoder/decoder/inspection. `encode(Bytes, Bytes, EncodeOptions)` takes basis and updated data; it is a neighboring binary-delta component, not the receiver-signature matching API implemented here. |
| `Yingqingxue/mooncas` | Registry metadata | Content-addressed storage kernel. This project contains no persistent object store. Source-level overlap not assessed. |

Primary-purpose overlaps **do exist** (incremental synchronization and backup). The proposed ecosystem
gap is specifically receiver-signature-driven rsync-style matching with independently verified
reconstruction. Different mechanisms are evidence of differentiation, not proof that a reviewer will
accept it as a new project. A requirement of literally no shared functionality with any work is not met.

## GitHub searches and limitations

- `rsync moonbit in:name,description,readme`: 17 repositories, search response marked complete.
  Results included collection repositories, the official skills repository and an Asciidoctor port;
  no dedicated MoonBit rsync implementation was identified from the returned metadata.
- `librsync language:MoonBit`: 0 repositories, search response marked complete.
- Follow-up `rsync language:MoonBit` was rate-limited. It is **not** a zero-result search.
- GitHub code search, private repositories, unindexed repositories, non-GitHub hosts, unpublished
  competition submissions and Mooncakes source code for every package were not exhaustively searched.
- Package metadata can omit functionality; only the nearby projects above received deeper inspection.

## Rejected candidates

- CIDR, structured HTTP fields, URI templates, Unicode layout and physical quantities: existing
  Mooncakes implementations were identified, so these were not selected.
- Cap'n Proto: name searches initially returned zero, but a broader readme/language search found
  `peter-jerry-ye/capnp`, with encoder, decoder and pointer source files. Rejected before creation.
- Gossip membership: existing MoonBit gossip simulators were identified. Not selected.

## Conclusion

Within the recorded scope, no exact published or returned-metadata MoonBit implementation of the
receiver-signature workflow was identified. Nearby functional overlap is real and disclosed.
This is an implementation of a known algorithm, not a globally unique invention. Search again before
submission, and explain why this distinct mechanism is useful rather than claiming absolute uniqueness.
