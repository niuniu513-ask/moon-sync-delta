"""Independent Python/hashlib oracle for the Node-hosted MoonBit file workflow.

Run after: moon build cmd/files --target js --release
Uses synthetic data only; does not modify existing files or contact a network.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "_build/js/release/build/cmd/files/files.js"


def invoke(*args: object, success: bool = True) -> str:
    proc = subprocess.run(
        ["node", str(PROGRAM), *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if (proc.returncode == 0) != success:
        raise AssertionError(f"Unexpected exit {proc.returncode}: {proc.stdout}\n{proc.stderr}")
    return proc.stdout.strip()


def check_signature(wire: bytes, basis: bytes, block: int) -> None:
    assert wire[:4] == b"MSIG"
    version, size, length = struct.unpack_from("<III", wire, 4)
    assert (version, size, length) == (1, block, len(basis))
    assert wire[16:80] == hashlib.sha256(basis).hexdigest().encode("ascii")
    count, = struct.unpack_from("<I", wire, 80)
    assert count == (len(basis) + block - 1) // block
    assert len(wire) == 84 + 68 * count
    for i in range(count):
        data = basis[i * block:(i + 1) * block]
        a = sum(data) & 65535
        b = sum((len(data) - j) * byte for j, byte in enumerate(data)) & 65535
        weak, = struct.unpack_from("<I", wire, 84 + i * 68)
        assert weak == a | b << 16
        assert wire[88 + i * 68:152 + i * 68] == hashlib.sha256(data).hexdigest().encode("ascii")


def check_delta(wire: bytes, basis: bytes, updated: bytes) -> dict[str, int]:
    assert wire[:4] == b"MSDL"
    version, old_length, new_length = struct.unpack_from("<III", wire, 4)
    assert (version, old_length, new_length) == (1, len(basis), len(updated))
    assert wire[16:80] == hashlib.sha256(basis).hexdigest().encode("ascii")
    assert wire[80:144] == hashlib.sha256(updated).hexdigest().encode("ascii")
    count, = struct.unpack_from("<I", wire, 144)
    pos = 148
    out = bytearray()
    literal = copied = 0
    for _ in range(count):
        tag = wire[pos]
        pos += 1
        if tag == 0:
            size, = struct.unpack_from("<I", wire, pos)
            pos += 4
            out.extend(wire[pos:pos + size])
            pos += size
            literal += size
        elif tag == 1:
            start, size = struct.unpack_from("<II", wire, pos)
            pos += 8
            assert 0 <= start <= len(basis) and 0 < size <= len(basis) - start
            out.extend(basis[start:start + size])
            copied += size
        else:
            raise AssertionError(f"Unknown operation: {tag}")
    assert pos == len(wire)
    assert bytes(out) == updated
    return {"copied_bytes": copied, "literal_bytes": literal, "delta_bytes": len(wire)}


def main() -> None:
    if not PROGRAM.is_file():
        raise SystemExit("Build first: moon build cmd/files --target js --release")
    rng = random.Random(20261011)
    basis = bytes(rng.randrange(256) for _ in range(65536))
    scenarios = {
        "backup_insert": b"backup-v2\0" + basis,
        "asset_replace": basis[:8192] + b"asset-v2" * 4 + basis[8224:],
        "replica_append": basis + b"new-record\n" * 32,
        "empty": b"",
        "reorder": basis[32768:] + basis[:32768],
        "fully_changed": bytes(rng.randrange(256) for _ in range(65536)),
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="moon-sync-delta-") as work:
        folder = Path(work)
        old = folder / "old.bin"
        old.write_bytes(basis)
        sig = folder / "signature.bin"
        invoke("signature", old, sig, 512)
        check_signature(sig.read_bytes(), basis, 512)
        inspection = invoke("inspect", sig)
        assert "type=signature" in inspection and "blocks=128," in inspection
        assert f"sha256={hashlib.sha256(basis).hexdigest()}" in inspection
        for name, updated in scenarios.items():
            new, patch, restored = (folder / f"{name}.{suffix}" for suffix in ("new", "delta", "restored"))
            new.write_bytes(updated)
            invoke("delta", sig, new, patch)
            metrics = check_delta(patch.read_bytes(), basis, updated)
            inspection = invoke("inspect", patch)
            assert "type=delta" in inspection
            assert f"output_sha256={hashlib.sha256(updated).hexdigest()}" in inspection
            invoke("apply", old, patch, restored)
            assert restored.read_bytes() == updated
            # The adapter refuses to overwrite an existing output.
            invoke("apply", old, patch, restored, success=False)
            assert restored.read_bytes() == updated
            results.append({"scenario": name, "output_bytes": len(updated),
                            "signature_bytes": sig.stat().st_size,
                            "total_wire_bytes": sig.stat().st_size + patch.stat().st_size,
                            **metrics, "exact": True})
        wrong = folder / "wrong.bin"
        wrong.write_bytes(basis[:-1] + bytes([basis[-1] ^ 1]))
        rejected_output = folder / "must-not-exist.bin"
        invoke("apply", wrong, folder / "backup_insert.delta", rejected_output, success=False)
        assert not rejected_output.exists()
        corrupted = folder / "corrupted.delta"
        data = bytearray((folder / "backup_insert.delta").read_bytes())
        data[153] ^= 1  # First literal byte; structural parse still succeeds.
        corrupted.write_bytes(data)
        invoke("apply", old, corrupted, rejected_output, success=False)
        assert not rejected_output.exists()
        corrupted.write_bytes(b"MSDL")
        invoke("inspect", corrupted, success=False)
        invoke("apply", old, corrupted, rejected_output, success=False)
        assert not rejected_output.exists()
    print(json.dumps({"oracle": "Python hashlib + independent frame reader",
                      "data": "controlled synthetic bytes, not a production benchmark",
                      "scenarios": results, "negative_checks": "passed"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
