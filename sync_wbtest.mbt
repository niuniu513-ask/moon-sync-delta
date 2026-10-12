///|
fn roundtrip(basis : Bytes, updated : Bytes, block : Int) -> Delta raise {
  let sig = decode_signature(
    encode_signature(signature(basis, block_size=block)),
  )
  let delta = create_delta(sig, updated)
  let decoded = decode_delta(encode_delta(delta))
  assert_eq(apply_delta(basis, decoded), updated)
  verify_delta(basis, decoded)
  assert_eq(encode_delta(decoded), encode_delta(delta))
  assert_eq(delta.statistics().wire_bytes, encode_delta(delta).length())
  delta
}

///|
test "verification rejects bad operations checksums lengths and budgets" {
  let delta = create_delta(signature(b"old-data", block_size=4), b"new-data")
  for
    bad in [
      Delta::{ ..delta, operations: [Copy(8, 1)], },
      Delta::{ ..delta, operations: [Literal(b"")], },
      Delta::{ ..delta, output_length: 1, },
      Delta::{ ..delta, output_length: 9, },
      Delta::{ ..delta, output_digest: digest(b"wrong"[:]), },
    ] {
    let rejected = try verify_delta(b"old-data", bad) catch {
      CorruptData(_) => true
      _ => false
    } noraise {
      _ => false
    }
    assert_true(rejected)
  }
  let rejected = try verify_delta(b"OLD-data", delta) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
  let limited = Limits::{ ..Limits::default(), max_operations: 0, }
  let rejected = try verify_delta(b"old-data", delta, limits=limited) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}

///|
test "signature cost agrees with encoding across block geometries" {
  for n = 0; n < 40; n = n + 1 {
    let basis = Bytes::makei(n, fn(i) { i.to_byte() })
    for block in [1, 3, 16, 2048] {
      let sig = signature(basis, block_size=block)
      assert_eq(sig.wire_size(), encode_signature(sig).length())
    }
  }
}

///|
test "receiver can select a basis by length and digest without reconstruction" {
  let delta = create_delta(signature(b"version1"), b"version2-longer")
  assert_eq(delta.basis_length(), 8)
  assert_eq(delta.basis_digest(), digest(b"version1"[:]))
  assert_eq(delta.output_length(), 15)
  assert_true(delta.matches_basis(b"version1"))
  assert_true(!delta.matches_basis(b"version0"))
  assert_true(!delta.matches_basis(b"short"))
  let limited = Limits::{ ..Limits::default(), max_bytes: 7, }
  let rejected = try delta.matches_basis(b"short", limits=limited) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}

///|
test "standard SHA-256 vectors and unsigned rolling checksum" {
  assert_eq(
    digest(b""[:]),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    digest(b"abc"[:]),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(rolling_checksum(b"abc"[:]), 0x024a0126U)
}

///|
test "rolling checksum equals independent window recomputation" {
  let data = Bytes::makei(310, fn(i) { ((i * 73 + 219) % 256).to_byte() })
  for size = 1; size < 71; size = size + 1 {
    let mut weak = rolling_checksum(data[:size])
    for pos = 0; pos < data.length() - size; pos = pos + 1 {
      weak = roll_checksum(weak, data[pos], data[pos + size], size)
      assert_eq(weak, rolling_checksum(data[pos + 1:pos + 1 + size]))
    }
  }
}

///|
test "empty creation deletion and identical data" {
  assert_eq(roundtrip(b"", b"", 4).operations(), [])
  assert_eq(roundtrip(b"", b"created", 4).statistics().copied_bytes, 0)
  assert_eq(roundtrip(b"deleted", b"", 4).operations(), [])
  let delta = roundtrip(b"abcdefghijklmnopqr", b"abcdefghijklmnopqr", 4)
  assert_eq(delta.operations(), [Copy(0, 18)])
}

///|
test "front insertion resynchronizes complete blocks" {
  let basis = b"AAAABBBBCCCCDDDD"
  let delta = roundtrip(basis, b"new!" + basis, 4)
  assert_eq(delta.operations(), [Literal(b"new!"), Copy(0, 16)])
}

///|
test "deletion middle edit and block reorder" {
  assert_eq(
    roundtrip(b"AAAABBBBCCCCDDDD", b"BBBBCCCCDDDD", 4).statistics().copied_bytes,
    12,
  )
  assert_eq(
    roundtrip(b"AAAABBBBCCCCDDDD", b"AAAAxxxxCCCCDDDD", 4).statistics().literal_bytes,
    4,
  )
  assert_eq(
    roundtrip(b"AAAABBBBCCCCDDDD", b"DDDDAAAACCCCBBBB", 4).statistics().literal_bytes,
    0,
  )
}

///|
test "short final block may match away from target end" {
  let delta = roundtrip(b"ABCDEFGHxy", b"xy---ABCDEFGHxy", 4)
  assert_eq(delta.statistics().copied_bytes, 12)
  assert_eq(delta.statistics().literal_bytes, 3)
  assert_eq(roundtrip(b"xy", b"x---xy---", 2048).statistics().copied_bytes, 2)
}

///|
test "weak checksum collision never causes a copy" {
  // Equal sum and equal weighted sum; the two blocks contain different bytes.
  let left = b"\x0a\x0a\x0a"
  let right = b"\x0b\x08\x0b"
  assert_eq(rolling_checksum(left[:]), rolling_checksum(right[:]))
  assert_true(digest(left[:]) != digest(right[:]))
  assert_eq(roundtrip(left, right, 3).operations(), [Literal(right)])
}

///|
test "duplicate blocks choose first offset deterministically" {
  let delta = roundtrip(b"ABCDABCDABCD", b"ABCD", 4)
  assert_eq(delta.operations(), [Copy(0, 4)])
  let exposed = delta.operations()
  exposed.clear()
  assert_eq(delta.operations(), [Copy(0, 4)])
}

///|
test "binary data supports every byte and large positive block size" {
  let basis = Bytes::makei(256, fn(i) { i.to_byte() })
  let updated = b"\x00\xff" + basis + b"\xfe\x00"
  let _ = roundtrip(basis, updated, 16)
  let _ = roundtrip(basis, updated, 512 * 1024 * 1024)
  let _ = roundtrip(basis, basis[:3].to_owned(), 256)
}

///|
test "bounded randomized edits preserve exact bytes" {
  let mut seed = 0x13579bdfU
  for trial = 0; trial < 200; trial = trial + 1 {
    let n = trial % 79
    let basis = Bytes::makei(n, fn(_i) {
      seed = seed * 1664525U + 1013904223U
      (seed >> 24).to_byte()
    })
    let cut = if n == 0 { 0 } else { trial % n }
    let updated = basis[cut:].to_owned() +
      b"\x00\xffedited" +
      basis[:cut].to_owned()
    let block = trial % 17 + 1
    let _ = roundtrip(basis, updated, block)
  }
}

///|
test "wrong basis and corrupted output fail explicitly" {
  let delta = create_delta(signature(b"old-data", block_size=4), b"new-data")
  let wrong = try apply_delta(b"OLD-data", delta) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(wrong)
  let bad = Delta::{ ..delta, output_digest: digest(b"wrong"[:]), }
  let rejected = try apply_delta(b"old-data", bad) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}

///|
test "invalid parameters and strict resource budgets are rejected" {
  let bad = try signature(b"x", block_size=0) catch {
    InvalidInput(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(bad)
  let small = Limits::{ max_bytes: 3, max_blocks: 1, max_operations: 1, }
  let bytes_limited = try signature(b"abcd", limits=small) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(bytes_limited)
  let blocks_limited = try signature(b"abc", block_size=1, limits=small) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(blocks_limited)
  let invalid_limits = Limits::{
    max_bytes: -1,
    max_blocks: 0,
    max_operations: 0,
  }
  let invalid = try signature(b"", limits=invalid_limits) catch {
    InvalidInput(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(invalid)
}

///|
test "operation count and frame byte budgets are enforced" {
  let sig = signature(b"AAAABBBB", block_size=4)
  let limited = Limits::{ max_bytes: 1024, max_blocks: 4, max_operations: 1, }
  let rejected = try create_delta(sig, b"AAAA----BBBB", limits=limited) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
  let tiny = Limits::{ max_bytes: 8, max_blocks: 4, max_operations: 4, }
  let rejected = try encode_signature(sig, limits=tiny) catch {
    LimitExceeded(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}

///|
test "transmission recommendation accounts for both frame overheads" {
  let basis = b"abcdefgh".repeat(64)
  let sig = signature(basis, block_size=512)
  let delta = create_delta(sig, basis)
  assert_true(delta.worth_sending())
  assert_true(
    delta.worth_sending(signature_bytes=encode_signature(sig).length()),
  )
  assert_true(!delta.worth_sending(signature_bytes=500))
  assert_true(!create_delta(signature(b""), b"new").worth_sending())
  assert_true(!create_delta(signature(b""), b"").worth_sending())
  let rejected = try delta.worth_sending(signature_bytes=-1) catch {
    InvalidInput(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}
