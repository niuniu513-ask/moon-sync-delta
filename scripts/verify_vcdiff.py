"""Independent RFC3284 ADD/COPY SELF oracle and end-to-end extension checks.

This is deliberately a decoder only for the documented generated profile,
not a second general-purpose VCDIFF implementation. Uses synthetic fixtures.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import struct
import tempfile

from verify_files import invoke


def decode_profile(wire: bytes, basis: bytes) -> bytes:
    assert wire[:5] == bytes.fromhex("d6c3c40000")
    pos = 5

    def integer() -> int:
        nonlocal pos
        value = 0
        for _ in range(5):
            byte = wire[pos]
            pos += 1
            value = (value << 7) | (byte & 127)
            if byte < 128:
                return value
        raise AssertionError("overlong varint")

    indicator = wire[pos]
    pos += 1
    assert indicator in (0, 1)
    source = b""
    if indicator:
        length, offset = integer(), integer()
        assert offset == 0 and length == len(basis)
        source = basis[offset:offset + length]
    delta_size = integer()
    end = pos + delta_size
    target_size = integer()
    assert wire[pos] == 0
    pos += 1
    data_size, instruction_size, address_size = integer(), integer(), integer()
    data_pos = pos
    instruction_pos = pos + data_size
    address_pos = instruction_pos + instruction_size
    instruction_end = address_pos
    assert address_pos + address_size == end == len(wire)
    pos = instruction_pos
    output = bytearray()
    while pos < instruction_end:
        opcode = wire[pos]
        pos += 1
        size = integer()
        assert size > 0
        if opcode == 1:  # RFC3284 default table: ADD variable size
            assert data_pos + size <= instruction_pos
            output.extend(wire[data_pos:data_pos + size])
            data_pos += size
        elif opcode == 19:  # COPY variable size, address mode SELF
            saved = pos
            pos = address_pos
            offset = integer()
            address_pos = pos
            pos = saved
            assert offset + size <= len(source)
            output.extend(source[offset:offset + size])
        else:
            raise AssertionError(f"unsupported profile opcode {opcode}")
        assert len(output) <= target_size
    assert pos == instruction_end
    assert data_pos == instruction_pos and address_pos == end
    assert len(output) == target_size
    return bytes(output)


def main() -> None:
    rng = random.Random(20261016)
    old_bytes = bytes(rng.randrange(256) for _ in range(65536))
    cases = {
        "identical": old_bytes,
        "prepend": b"v2\0" + old_bytes,
        "append": old_bytes + b"record\n" * 32,
        "replace": old_bytes[:8192] + b"x" * 32 + old_bytes[8224:],
        "delete": old_bytes[512:],
        "reorder": old_bytes[32768:] + old_bytes[:32768],
        "unrelated": bytes(rng.randrange(256) for _ in range(65536)),
        "empty_target": b"",
    }
    results = []
    with tempfile.TemporaryDirectory(prefix="moon-vcdiff-extension-") as temp:
        root = Path(temp)
        receiver, sender = root / "receiver", root / "sender"
        receiver.mkdir()
        sender.mkdir()
        old, sig = receiver / "old.bin", sender / "remote.sig"
        old.write_bytes(old_bytes)
        invoke("signature", old, sig, 512)
        for name, target in cases.items():
            new, packet, raw = (sender / f"{name}.{ext}" for ext in ("new", "msvf", "vcdiff"))
            result = receiver / f"{name}.result"
            new.write_bytes(target)
            # Temporarily remove the receiver file: sender has only signature + new.
            offline = receiver / "offline.bin"
            old.rename(offline)
            try:
                report = invoke("vcdiff", sig, new, packet)
            finally:
                offline.rename(old)
            invoke("vcdiff-export", packet, raw)
            payload = raw.read_bytes()
            assert decode_profile(payload, old_bytes) == target
            wire = packet.read_bytes()
            assert wire[:8] == b"MSVF\x01\0\0\0"
            assert struct.unpack_from("<I", wire, 8)[0] == len(old_bytes)
            assert wire[12:76] == hashlib.sha256(old_bytes).hexdigest().encode()
            assert struct.unpack_from("<I", wire, 76)[0] == len(target)
            assert wire[80:144] == hashlib.sha256(target).hexdigest().encode()
            assert struct.unpack_from("<I", wire, 144)[0] == len(payload)
            assert wire[148:] == payload
            invoke("vcdiff-apply", old, packet, result)
            assert result.read_bytes() == target
            invoke("vcdiff-apply", old, packet, result, success=False)
            assert result.read_bytes() == target  # no overwrite
            total = len(sig.read_bytes()) + len(wire)
            assert f"total_wire={total}," in report
            assert f"recommend={'delta' if total < len(target) else 'full'}" in report
            results.append({"case": name, "target": len(target), "payload": len(payload), "total_wire": total})
        packet = sender / "prepend.msvf"
        bad_basis = receiver / "stale.bin"
        bad_basis.write_bytes(b"X" + old_bytes[1:])
        absent = receiver / "must-not-exist.bin"
        invoke("vcdiff-apply", bad_basis, packet, absent, success=False)
        assert not absent.exists()
        original = packet.read_bytes()
        # Invalid structure, wrong output hash, valid structure with changed ADD data,
        # truncation, wrong dictionary length, trailing bytes, unsupported version.
        corruptions = [original[:-1], original + b"x"]
        for offset in (4, 8, 80, 148, len(original) - 6):
            changed = bytearray(original)
            changed[offset] ^= 1
            corruptions.append(bytes(changed))
        for i, wire in enumerate(corruptions):
            bad = sender / f"bad-{i}.msvf"
            bad.write_bytes(wire)
            invoke("vcdiff-apply", old, bad, absent, success=False)
            assert not absent.exists()
        # Empty basis + tiny new data: protocol overhead makes full transfer cheaper.
        empty, empty_sig, tiny = receiver / "empty", sender / "empty.sig", sender / "tiny"
        empty.write_bytes(b"")
        tiny.write_bytes(b"new")
        invoke("signature", empty, empty_sig, 512)
        tiny_packet = sender / "tiny.msvf"
        assert "recommend=full" in invoke("vcdiff", empty_sig, tiny, tiny_packet)
        assert decode_profile(tiny_packet.read_bytes()[148:], b"") == b"new"
    print(json.dumps({"extension_cases": results, "negative_cases": "passed", "empty_basis": "passed"}, indent=2))


if __name__ == "__main__":
    main()
