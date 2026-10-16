///|
fn vcd_roundtrip(basis : Bytes, target : Bytes, block : Int) -> Unit raise {
  let sig = decode_signature(
    encode_signature(signature(basis, block_size=block)),
  )
  let transfer = create_vcdiff(sig, target)
  let wire = encode_vcdiff_transfer(transfer)
  let received = decode_vcdiff_transfer(wire)
  assert_eq(apply_vcdiff(basis, received), target)
  // Independent consumer: no project envelope, no apply_delta, actual dependency.
  assert_eq(
    @vcdiff.decode(basis, received.payload(), @vcdiff.default_decode_limits()),
    target,
  )
  assert_eq(@vcdiff.validate_structure(received.payload()), 1)
  assert_eq(create_vcdiff(sig, target).payload(), received.payload())
}

///|
test "VCDIFF interoperates with upstream across binary edits and varint widths" {
  for size in [0, 1, 3, 127, 128, 255, 16384, 17000] {
    let basis = Bytes::makei(size, fn(i) {
      ((i * 17 + i / 251) % 256).to_byte()
    })
    for block in [1, 7, 512] {
      vcd_roundtrip(basis, basis, block)
      let inserted = [b"prefix", basis, b"suffix"]
      let out : Array[Byte] = []
      for bytes in inserted {
        put_bytes(out, bytes[:])
      }
      vcd_roundtrip(basis, Bytes::from_array(out[:]), block)
      vcd_roundtrip(basis, b"", block)
    }
  }
  vcd_roundtrip(b"AAAABBBBCCCCDDDD", b"DDDDBBBBAAAACCCC", 4)
  vcd_roundtrip(b"same-same-same", b"\x00\xff\x80different", 4)
}

///|
test "VCDIFF genuinely reuses signed source blocks without encoder basis" {
  let basis = Bytes::makei(8192, fn(i) { ((i * 13 + i / 127) % 256).to_byte() })
  let target = Bytes::makei(8193, fn(i) {
    if i == 0 {
      255
    } else {
      basis[i - 1]
    }
  })
  let transfer = create_vcdiff(signature(basis, block_size=256), target)
  let summary = @vcdiff.inspect(transfer.payload())
  assert_true(summary.uses_source)
  assert_true(summary.copy_count > 0)
  assert_true(transfer.payload().length() < target.length())
  assert_eq(apply_vcdiff(basis, transfer), target)
}

///|
test "VCDIFF rejects stale basis tampered payload metadata truncation and trailing bytes" {
  let transfer = create_vcdiff(
    signature(b"AAAABBBBCCCC", block_size=4),
    b"AAAABBBB-new",
  )
  let stale = try apply_vcdiff(b"AAAABBBBCCCD", transfer) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(stale)
  for
    bad in [
      VcdiffTransfer::{ ..transfer, output_digest: digest(b"wrong"[:]), },
      VcdiffTransfer::{ ..transfer, output_length: 1, },
      VcdiffTransfer::{ ..transfer, payload: b"not-vcdiff", },
      VcdiffTransfer::{
        ..transfer,
        payload: @vcdiff.encode(b"", b"wrong", @vcdiff.default_encode_options()),
      },
    ] {
    let rejected = try apply_vcdiff(b"AAAABBBBCCCC", bad) catch {
      CorruptData(_) => true
      _ => false
    } noraise {
      _ => false
    }
    assert_true(rejected)
  }
  let wire = encode_vcdiff_transfer(transfer)
  for n = 0; n < wire.length(); n = n + 1 {
    let rejected = try decode_vcdiff_transfer(wire[:n].to_owned()) catch {
      _ => true
    } noraise {
      _ => false
    }
    assert_true(rejected)
  }
  let extra : Array[Byte] = []
  put_bytes(extra, wire[:])
  extra.push(0)
  let rejected = try decode_vcdiff_transfer(Bytes::from_array(extra[:])) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
}

///|
test "VCDIFF enforces frame output and operation budgets" {
  let transfer = create_vcdiff(
    signature(b"AAAABBBBCCCC", block_size=4),
    b"AAAABBBB-new",
  )
  for
    limits in [
      Limits::{ ..Limits::default(), max_bytes: 10, },
      Limits::{ ..Limits::default(), max_operations: 0, },
      Limits::{ ..Limits::default(), max_bytes: -1, },
    ] {
    let rejected = try apply_vcdiff(b"AAAABBBBCCCC", transfer, limits~) catch {
      _ => true
    } noraise {
      _ => false
    }
    assert_true(rejected)
  }
}
