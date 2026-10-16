# Remote-signature VCDIFF extension

## Responsibility and data flow

Receiver basis -> MSIG signature -> sender(signature, target) -> standard VCDIFF + MSVF integrity metadata -> receiver upstream decoder -> verified target.

The sender entry `create_vcdiff(Signature, Bytes)` has no basis-byte input. Signature checksums leak equality information; this is a bandwidth technique, not a secrecy or authentication protocol. Strong matching and old/new whole-file SHA-256 checks mitigate accidental mismatch, not a malicious sender who controls all metadata.

`yangxixi00/moon_vcdiff@0.1.0` provides the default code table, RFC base-128 integer encoding, structure inspection and decoding. This project translates its own signature-driven Copy/Literal plan to a standard single-window stream; it does not invoke the upstream two-file encoder during generation. The upstream two-file encoder is used only as a documented baseline in the example.

## Generated standard payload profile

RFC3284 header `D6 C3 C4 00 00`; one window, even for empty output. VCD_SOURCE with the whole signed basis at position zero iff there is a Copy. Otherwise no dictionary. No VCD_TARGET, application header, custom code table or secondary compression.

Each literal uses default-table variable-size ADD (index 1). Each copy uses variable-size COPY SELF mode (index 19), absolute address in the old source dictionary. Generation obtains opcodes by querying the dependency's default table, not by maintaining a separate code table. Window and section sizes use the dependency's integer encoder. Payloads are checked with upstream inspect and decoded with explicit output/window/instruction budgets.

`VcdiffTransfer.payload()` and `vcdiff-export` provide just the standard bytes. Interoperability is verified with the published moon_vcdiff decoder and an independent Python profile decoder. No xdelta/librsync interoperability run or full RFC encoder conformance is claimed.

## MSVF v1 integrity envelope

| Offset | Value |
|---|---|
| 0 | ASCII MSVF (4 bytes) |
| 4 | version=1 (u32 little endian) |
| 8 | basis byte length (u32 little endian) |
| 12 | basis SHA-256 (64 lowercase ASCII hex bytes) |
| 76 | output byte length (u32 little endian) |
| 80 | output SHA-256 (64 lowercase ASCII hex bytes) |
| 144 | payload byte length (u32 little endian) |
| 148 | standard VCDIFF payload |

No trailing bytes. Digests and lengths are checked; window source geometry must match the signed basis. At most one window and no target dictionary in accepted transfers. A valid but altered ADD payload must fail whole-output SHA-256 before an output file is opened. Raw exported VCDIFF omits these metadata checks.

The MSVF envelope is a project format and is not itself RFC3284. MSIG stays at version 1, specified in WIRE_FORMAT.md. Legacy MSDL remains compatible; it is not the primary 0.2 delivery format.

## Cost and limits

Total cold-exchange cost = encoded signature length + 148 + VCDIFF payload length. For an already cached signature the request cost can differ; the CLI deliberately reports the cold-exchange cost. A small payload alone does not prove bandwidth savings.

Uses existing Limits: input/output/frame max_bytes, signature max_blocks, plan/decoder max_operations. Defaults 64 MiB and 100,000 blocks/operations. Buffers, signature index and output all consume memory beyond these individual limits. No streaming or network layer is provided.
