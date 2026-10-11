///|
fn mutate(data : Bytes, offset : Int, value : Byte) -> Bytes {
  let bytes = data.to_array()
  bytes[offset] = value
  Bytes::from_array(bytes[:])
}

///|
fn rejects_signature(data : Bytes) -> Bool {
  try decode_signature(data) catch {
    _ => true
  } noraise {
    _ => false
  }
}

///|
fn rejects_delta(data : Bytes) -> Bool {
  try decode_delta(data) catch {
    _ => true
  } noraise {
    _ => false
  }
}

///|
test "all truncated signature and delta prefixes are rejected" {
  let sig = signature(b"AAAABBBBxy", block_size=4)
  let wire = encode_signature(sig)
  for i = 0; i < wire.length(); i = i + 1 {
    assert_true(rejects_signature(wire[:i].to_owned()))
  }
  let wire = encode_delta(create_delta(sig, b"AAAAnewBBBBxy"))
  for i = 0; i < wire.length(); i = i + 1 {
    assert_true(rejects_delta(wire[:i].to_owned()))
  }
}

///|
test "wrong type version and trailing data fail" {
  let sig = signature(b"abc", block_size=4)
  let sw = encode_signature(sig)
  let dw = encode_delta(create_delta(sig, b"abc"))
  assert_true(rejects_signature(dw))
  assert_true(rejects_delta(sw))
  assert_true(rejects_signature(mutate(sw, 4, b'\x02')))
  assert_true(rejects_delta(mutate(dw, 4, b'\x02')))
  assert_true(rejects_signature(sw + b"\x00"))
  assert_true(rejects_delta(dw + b"\x00"))
}

///|
test "signature geometry and digest syntax are validated" {
  let sw = encode_signature(signature(b"abc", block_size=4))
  assert_true(rejects_signature(mutate(sw, 8, b'\x00')))
  assert_true(rejects_signature(mutate(sw, 80, b'\x02')))
  assert_true(rejects_signature(mutate(sw, 16, b'Z')))
  assert_true(rejects_signature(mutate(sw, 88, b'\xff')))
}

///|
test "delta copy bounds zero lengths unknown tags and huge counts fail" {
  let dw = encode_delta(
    create_delta(signature(b"abcdefgh", block_size=4), b"abcdefgh"),
  )
  assert_true(rejects_delta(mutate(dw, 148, b'\x02')))
  assert_true(rejects_delta(mutate(dw, 149, b'\x09')))
  assert_true(rejects_delta(mutate(dw, 153, b'\x00')))
  assert_true(rejects_delta(mutate(dw, 156, b'\xff')))
  assert_true(rejects_delta(mutate(dw, 147, b'\xff')))
  assert_true(rejects_delta(mutate(dw, 12, b'\x07')))
  assert_true(rejects_delta(mutate(dw, 16, b'\x00')))
}

///|
test "literal payload corruption is detected on apply" {
  let delta = create_delta(signature(b""), b"new-payload")
  let wire = encode_delta(delta)
  let altered = mutate(wire, 153, b'X')
  let parsed = decode_delta(altered)
  let rejected = try apply_delta(b"", parsed) catch {
    CorruptData(_) => true
    _ => false
  } noraise {
    _ => false
  }
  assert_true(rejected)
  assert_true(rejects_delta(mutate(wire, 149, b'\x00')))
}

///|
test "malformed arbitrary frames never cause a bounds panic" {
  let mut seed = 11U
  for n = 0; n < 300; n = n + 1 {
    let bytes = Bytes::makei(n, fn(_i) {
      seed = seed * 1664525U + 1013904223U
      (seed >> 24).to_byte()
    })
    assert_true(rejects_signature(bytes))
    assert_true(rejects_delta(bytes))
  }
}
