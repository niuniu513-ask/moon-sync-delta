///|
fn demonstrate(label : String, basis : Bytes, updated : Bytes) -> Unit raise {
  // Receiver sends only these signatures to the sender.
  let sig_wire = @sync.encode_signature(@sync.signature(basis, block_size=512))
  // Sender does not receive or read the old bytes.
  let received_sig = @sync.decode_signature(sig_wire)
  let transfer = @sync.create_vcdiff(received_sig, updated)
  let delta_wire = @sync.encode_vcdiff_transfer(transfer)
  // Receiver validates old and reconstructed data.
  let result = @sync.apply_vcdiff(
    basis,
    @sync.decode_vcdiff_transfer(delta_wire),
  )
  assert_eq(result, updated)
  // Actual upstream consumption of the standard payload (without MSVF wrapper).
  assert_eq(
    @vcdiff.decode(basis, transfer.payload(), @vcdiff.default_decode_limits()),
    updated,
  )
  // Baseline needs both files. Sizes describe this fixture, not a universal win.
  let baseline = @vcdiff.encode(
    basis,
    updated,
    @vcdiff.default_encode_options(),
  )
  println(
    "\{label}: output=\{updated.length()}, signature_wire=\{sig_wire.length()}, vcdiff_payload=\{transfer.payload().length()}, transfer_wire=\{delta_wire.length()}, total_wire=\{sig_wire.length() + delta_wire.length()}, upstream_two_file_payload=\{baseline.length()}, upstream_decode=true, exact=true",
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
    demonstrate(
      "application resource: prepend metadata",
      basis,
      b"resource-v2\x00" + basis,
    )
    demonstrate(
      "offline data package: replace 32 bytes",
      basis,
      basis[:8192].to_owned() + b"asset-v2".repeat(4) + basis[8224:].to_owned(),
    )
    demonstrate(
      "cached binary data: append records",
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
