# MoonSyncDelta wire version 1

This document covers MSIG and the retained legacy MSDL format. Version 0.2 primarily
delivers standard VCDIFF with an MSVF metadata envelope; see [VCDIFF_EXTENSION.md](VCDIFF_EXTENSION.md).

This is the project's own framed representation, not rsync/librsync wire compatibility.
All integers are unsigned little-endian 32-bit integers. Hashes are 64 lowercase ASCII hex characters
representing SHA-256. Bytes have no text encoding assumptions. Trailing bytes are rejected.

## Signature frame

| Byte offset | Field |
|---|---|
| 0 | `MSIG` (4 bytes) |
| 4 | Version, currently 1 |
| 8 | Positive block size |
| 12 | Basis byte length |
| 16 | Basis SHA-256 (64 bytes) |
| 80 | Block count |
| 84 | Repeated block records: weak checksum (4), block SHA-256 (64) |

Block count must equal ceil(basis length / block size); empty basis has no blocks.
Block i starts at i * block size. Only the final block may be shorter.
For unsigned bytes x[0..n), `a = sum(x) mod 65536`,
`b = sum((n-i)*x[i]) mod 65536`, `weak = a | (b << 16)`.
Signature length is exactly 84 + 68 * block count.

## Delta frame

| Byte offset | Field |
|---|---|
| 0 | `MSDL` (4 bytes) |
| 4 | Version, currently 1 |
| 8 | Basis byte length |
| 12 | Reconstructed output byte length |
| 16 | Basis SHA-256 (64 bytes) |
| 80 | Output SHA-256 (64 bytes) |
| 144 | Operation count |
| 148 | Operations |

- Literal: byte tag 0, positive length (4), exactly that many literal bytes.
- Copy: byte tag 1, source byte offset (4), positive byte length (4).

Copy ranges must be entirely within the basis. Sum of operation lengths must equal declared output length.
Empty output uses zero operations. Unknown tags, invalid hashes, unsupported versions and trailing data fail.
Encoded length is 148 + sum(5 + literal length) + sum(9 for each copy).

Resource limits apply to frames, data sizes, block count and operation count before expensive loops/allocations.
Parsers reject values above the supported 512 MiB range. Parsing does not authenticate a sender.
Application verifies the complete basis hash and complete output hash before returning any reconstructed bytes.
