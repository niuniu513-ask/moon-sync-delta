///|
fn demonstrate(label : String, basis : Bytes, updated : Bytes) -> Unit raise {
  // Receiver sends only these signatures to the sender.
  let sig_wire = @sync.encode_signature(@sync.signature(basis, block_size=512))
  // Sender does not receive or read the old bytes.
  let received_sig = @sync.decode_signature(sig_wire)
  let delta = @sync.create_delta(received_sig, updated)
  let delta_wire = @sync.encode_delta(delta)
  // Receiver validates old and reconstructed data.
  let result = @sync.apply_delta(basis, @sync.decode_delta(delta_wire))
  assert_eq(result, updated)
  let s = delta.statistics()
  println(
    "\{label}: output=\{s.output_bytes}, reused=\{s.copied_bytes}, literal=\{s.literal_bytes}, signature_wire=\{sig_wire.length()}, delta_wire=\{delta_wire.length()}, total_wire=\{sig_wire.length() + delta_wire.length()}, exact=true",
  )
}

///|
fn main {
  let mut seed = 0x12345678U
  let basis = Bytes::makei(65_536, fn(_i) {
    seed = seed * 1664525U + 1013904223U
    (seed >> 24).to_byte()
  })
  try {
    demonstrate("backup: prepend metadata", basis, b"backup-v2\x00" + basis)
    demonstrate(
      "asset update: replace 32 bytes",
      basis,
      basis[:8192].to_owned() + b"asset-v2".repeat(4) + basis[8224:].to_owned(),
    )
    demonstrate(
      "replica: append records",
      basis,
      basis + b"new-record\n".repeat(32),
    )
    demonstrate("small file: full transfer is cheaper", b"old", b"new")
  } catch {
    error => {
      println("demo failed: \{error}")
      panic()
    }
  }
}
