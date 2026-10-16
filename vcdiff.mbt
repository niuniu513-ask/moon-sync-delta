///|
/// A standard VCDIFF payload plus version checks. The metadata is not authentication.
pub struct VcdiffTransfer {
  basis_length : Int
  basis_digest : String
  output_length : Int
  output_digest : String
  payload : Bytes
}

///|
pub fn VcdiffTransfer::payload(self : VcdiffTransfer) -> Bytes {
  self.payload
}

///|
pub fn VcdiffTransfer::output_digest(self : VcdiffTransfer) -> String {
  self.output_digest
}

///|
fn vcd_integer(out : Array[Byte], n : Int) -> Unit raise SyncError {
  let encoded = @vcdiff.encode_unsigned_integer(n) catch {
    _ => raise CorruptData("VCDIFF integer encoding failed")
  }
  put_bytes(out, encoded[:])
}

///|
// Query the dependency's default table rather than maintaining a second table.
fn vcd_opcode(kind : @vcdiff.InstructionKind) -> Byte raise SyncError {
  for i, entry in @vcdiff.default_code_table() {
    if entry.first.kind == kind &&
      entry.first.size == 0 &&
      entry.first.mode == 0 &&
      entry.second.kind == @vcdiff.Noop {
      return i.to_byte()
    }
  }
  raise CorruptData("dependency default table lacks required opcode")
}

///|
fn validate_transfer(
  t : VcdiffTransfer,
  limits : Limits,
) -> Unit raise SyncError {
  check_limits(limits)
  check_size(t.basis_length, limits)
  check_size(t.output_length, limits)
  check_size(t.payload.length() + 148, limits)
  let s = @vcdiff.inspect(t.payload) catch {
    _ => raise CorruptData("invalid VCDIFF structure")
  }
  if s.target_size != t.output_length || s.window_count > 1 || s.uses_target {
    raise CorruptData("unsupported remote-signature VCDIFF profile")
  }
  if s.add_count + s.run_count + s.copy_count > limits.max_operations {
    raise LimitExceeded("VCDIFF operation limit exceeded")
  }
  for w in s.windows {
    if w.source_kind == @vcdiff.SourceDictionary &&
      (w.source_position != 0 || w.source_size != t.basis_length) {
      raise CorruptData("VCDIFF dictionary does not match signed basis")
    }
  }
}

///|
/// Extends moon_vcdiff with an encoder whose sender never receives basis bytes.
/// Produces a single-window RFC 3284 default-table ADD/COPY SELF profile.
pub fn create_vcdiff(
  sig : Signature,
  updated : Bytes,
  limits? : Limits = Limits::default(),
) -> VcdiffTransfer raise SyncError {
  let plan = create_delta(sig, updated, limits~)
  let data : Array[Byte] = []
  let instructions : Array[Byte] = []
  let addresses : Array[Byte] = []
  let add = vcd_opcode(@vcdiff.Add)
  let copy = vcd_opcode(@vcdiff.Copy)
  let mut uses_source = false
  for op in plan.operations {
    match op {
      Literal(bytes) => {
        instructions.push(add)
        vcd_integer(instructions, bytes.length())
        put_bytes(data, bytes[:])
      }
      Copy(offset, length) => {
        uses_source = true
        instructions.push(copy)
        vcd_integer(instructions, length)
        vcd_integer(addresses, offset)
      }
    }
  }
  let body : Array[Byte] = []
  vcd_integer(body, updated.length())
  body.push(0) // No secondary compression.
  vcd_integer(body, data.length())
  vcd_integer(body, instructions.length())
  vcd_integer(body, addresses.length())
  for section in [data, instructions, addresses] {
    for byte in section {
      body.push(byte)
    }
  }
  let out : Array[Byte] = [0xd6, 0xc3, 0xc4, 0, 0]
  out.push(if uses_source { 1 } else { 0 })
  if uses_source {
    vcd_integer(out, sig.basis_length)
    vcd_integer(out, 0)
  }
  vcd_integer(out, body.length())
  for byte in body {
    out.push(byte)
  }
  let transfer = VcdiffTransfer::{
    basis_length: sig.basis_length,
    basis_digest: sig.basis_digest,
    output_length: updated.length(),
    output_digest: plan.output_digest,
    payload: Bytes::from_array(out[:]),
  }
  validate_transfer(transfer, limits)
  transfer
}

///|
/// Uses the actual upstream decoder, guarded by basis and output SHA-256 checks.
pub fn apply_vcdiff(
  basis : Bytes,
  transfer : VcdiffTransfer,
  limits? : Limits = Limits::default(),
) -> Bytes raise SyncError {
  validate_transfer(transfer, limits)
  if basis.length() != transfer.basis_length ||
    digest(basis[:]) != transfer.basis_digest {
    raise CorruptData("VCDIFF basis digest mismatch")
  }
  let decoder_limits = @vcdiff.DecodeLimits::new(
    max_output_size=limits.max_bytes,
    max_window_size=limits.max_bytes,
    max_windows=1,
    max_instructions_per_window=limits.max_operations,
  ) catch {
    _ => raise InvalidInput("invalid upstream decoder limits")
  }
  let output = @vcdiff.decode(basis, transfer.payload, decoder_limits) catch {
    _ => raise CorruptData("upstream VCDIFF decoder rejected payload")
  }
  if output.length() != transfer.output_length ||
    digest(output[:]) != transfer.output_digest {
    raise CorruptData("VCDIFF output digest mismatch")
  }
  output
}

///|
/// MSVF v1 carries metadata; payload() alone is the interoperable VCDIFF file.
pub fn encode_vcdiff_transfer(
  t : VcdiffTransfer,
  limits? : Limits = Limits::default(),
) -> Bytes raise SyncError {
  validate_transfer(t, limits)
  let out : Array[Byte] = []
  put_bytes(out, b"MSVF"[:])
  put_u32(out, 1U)
  put_u32(out, t.basis_length.reinterpret_as_uint())
  put_hash(out, t.basis_digest)
  put_u32(out, t.output_length.reinterpret_as_uint())
  put_hash(out, t.output_digest)
  put_u32(out, t.payload.length().reinterpret_as_uint())
  put_bytes(out, t.payload[:])
  Bytes::from_array(out[:])
}

///|
pub fn decode_vcdiff_transfer(
  wire : Bytes,
  limits? : Limits = Limits::default(),
) -> VcdiffTransfer raise SyncError {
  check_limits(limits)
  check_size(wire.length(), limits)
  let reader = Reader::{ data: wire, position: 0, }
  reader.header(b"MSVF")
  let basis_length = reader.length()
  let basis_digest = reader.hash()
  let output_length = reader.length()
  let output_digest = reader.hash()
  let payload_length = reader.length()
  let payload = reader.take(payload_length).to_owned()
  reader.finish()
  let transfer = VcdiffTransfer::{
    basis_length,
    basis_digest,
    output_length,
    output_digest,
    payload,
  }
  validate_transfer(transfer, limits)
  transfer
}
