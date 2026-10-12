///|
priv struct Reader {
  data : Bytes
  mut position : Int
}

///|
fn Reader::take(self : Reader, length : Int) -> BytesView raise SyncError {
  if length < 0 || length > self.data.length() - self.position {
    raise CorruptData("truncated frame")
  }
  let start = self.position
  self.position += length
  self.data[start:self.position]
}

///|
fn Reader::u32(self : Reader) -> UInt raise SyncError {
  let b = self.take(4)
  b[0].to_uint() |
  (b[1].to_uint() << 8) |
  (b[2].to_uint() << 16) |
  (b[3].to_uint() << 24)
}

///|
fn Reader::length(self : Reader) -> Int raise SyncError {
  let n = self.u32()
  if n > (512 * 1024 * 1024 : UInt) {
    raise LimitExceeded("wire integer exceeds supported range")
  }
  n.reinterpret_as_int()
}

///|
fn Reader::hash(self : Reader) -> String raise SyncError {
  let b = self.take(64)
  for c in b {
    let n = c.to_int()
    if !((n >= 48 && n <= 57) || (n >= 97 && n <= 102)) {
      raise CorruptData("invalid SHA-256 encoding")
    }
  }
  @utf8.decode(b, ignore_bom=true) catch {
    _ => raise CorruptData("invalid digest text")
  }
}

///|
fn Reader::header(self : Reader, magic : Bytes) -> Unit raise SyncError {
  if !self.take(4).equal_to_bytes(magic) {
    raise CorruptData("wrong frame type")
  }
  if self.u32() != 1U {
    raise CorruptData("unsupported wire version")
  }
}

///|
fn Reader::finish(self : Reader) -> Unit raise SyncError {
  if self.position != self.data.length() {
    raise CorruptData("trailing bytes")
  }
}

///|
fn put_bytes(out : Array[Byte], data : BytesView) -> Unit {
  for b in data {
    out.push(b)
  }
}

///|
fn put_u32(out : Array[Byte], n : UInt) -> Unit {
  for i = 0; i < 4; i = i + 1 {
    out.push(((n >> (8 * i)) & 255U).to_byte())
  }
}

///|
fn put_hash(out : Array[Byte], hash : String) -> Unit {
  put_bytes(out, @utf8.encode(hash[:])[:])
}

///|
/// A documented project frame, not the rsync or librsync wire protocol.
pub fn encode_signature(
  sig : Signature,
  limits? : Limits = Limits::default(),
) -> Bytes raise SyncError {
  check_limits(limits)
  if sig.blocks.length() > limits.max_blocks {
    raise LimitExceeded("signature block limit exceeded")
  }
  check_size(sig.basis_length, limits)
  check_size(sig.wire_size(), limits)
  let out : Array[Byte] = []
  put_bytes(out, b"MSIG"[:])
  put_u32(out, 1U)
  put_u32(out, sig.block_size.reinterpret_as_uint())
  put_u32(out, sig.basis_length.reinterpret_as_uint())
  put_hash(out, sig.basis_digest)
  put_u32(out, sig.blocks.length().reinterpret_as_uint())
  for block in sig.blocks {
    put_u32(out, block.weak)
    put_hash(out, block.strong)
  }
  Bytes::from_array(out[:])
}

///|
/// Validates lengths and block geometry before indexing any payload.
pub fn decode_signature(
  data : Bytes,
  limits? : Limits = Limits::default(),
) -> Signature raise SyncError {
  check_limits(limits)
  check_size(data.length(), limits)
  let reader = Reader::{ data, position: 0, }
  reader.header(b"MSIG")
  let block_size = reader.length()
  if block_size <= 0 {
    raise CorruptData("zero block size")
  }
  let basis_length = reader.length()
  check_size(basis_length, limits)
  let basis_digest = reader.hash()
  let count = reader.length()
  if count > limits.max_blocks {
    raise LimitExceeded("signature block limit exceeded")
  }
  let expected = if basis_length == 0 {
    0
  } else {
    (basis_length - 1) / block_size + 1
  }
  if count != expected || count > (data.length() - reader.position) / 68 {
    raise CorruptData("inconsistent signature block count")
  }
  let blocks : Array[BlockSignature] = []
  let mut offset = 0
  for _i = 0; _i < count; _i = _i + 1 {
    let length = Int::min(block_size, basis_length - offset)
    blocks.push({ offset, length, weak: reader.u32(), strong: reader.hash(), })
    offset += length
  }
  reader.finish()
  { block_size, basis_length, basis_digest, blocks, index: make_index(blocks), }
}

///|
pub fn encode_delta(
  delta : Delta,
  limits? : Limits = Limits::default(),
) -> Bytes raise SyncError {
  check_limits(limits)
  check_size(delta.basis_length, limits)
  check_size(delta.output_length, limits)
  check_size(delta.statistics().wire_bytes, limits)
  if delta.operations.length() > limits.max_operations {
    raise LimitExceeded("delta operation limit exceeded")
  }
  let out : Array[Byte] = []
  put_bytes(out, b"MSDL"[:])
  put_u32(out, 1U)
  put_u32(out, delta.basis_length.reinterpret_as_uint())
  put_u32(out, delta.output_length.reinterpret_as_uint())
  put_hash(out, delta.basis_digest)
  put_hash(out, delta.output_digest)
  put_u32(out, delta.operations.length().reinterpret_as_uint())
  for op in delta.operations {
    match op {
      Literal(data) => {
        out.push(b'\x00')
        put_u32(out, data.length().reinterpret_as_uint())
        put_bytes(out, data[:])
      }
      Copy(offset, length) => {
        out.push(b'\x01')
        put_u32(out, offset.reinterpret_as_uint())
        put_u32(out, length.reinterpret_as_uint())
      }
    }
  }
  Bytes::from_array(out[:])
}

///|
pub fn decode_delta(
  data : Bytes,
  limits? : Limits = Limits::default(),
) -> Delta raise SyncError {
  check_limits(limits)
  check_size(data.length(), limits)
  let reader = Reader::{ data, position: 0, }
  reader.header(b"MSDL")
  let basis_length = reader.length()
  let output_length = reader.length()
  check_size(basis_length, limits)
  check_size(output_length, limits)
  let basis_digest = reader.hash()
  let output_digest = reader.hash()
  let count = reader.length()
  if count > limits.max_operations {
    raise LimitExceeded("delta operation limit exceeded")
  }
  if count > (data.length() - reader.position) / 5 {
    raise CorruptData("inconsistent delta operation count")
  }
  let ops : Array[Operation] = []
  let mut produced = 0
  for _i = 0; _i < count; _i = _i + 1 {
    let tag = reader.take(1)[0].to_int()
    match tag {
      0 => {
        let length = reader.length()
        if length <= 0 || length > output_length - produced {
          raise CorruptData("invalid literal extent")
        }
        ops.push(Literal(reader.take(length).to_owned()))
        produced += length
      }
      1 => {
        let offset = reader.length()
        let length = reader.length()
        if offset > basis_length ||
          length <= 0 ||
          length > basis_length - offset ||
          length > output_length - produced {
          raise CorruptData("invalid copy extent")
        }
        ops.push(Copy(offset, length))
        produced += length
      }
      _ => raise CorruptData("unknown operation")
    }
  }
  if produced != output_length {
    raise CorruptData("inconsistent output length")
  }
  reader.finish()
  { basis_length, basis_digest, output_length, output_digest, operations: ops, }
}
