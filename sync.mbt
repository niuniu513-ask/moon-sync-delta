///|
fn make_index(
  blocks : Array[BlockSignature],
) -> Map[(Int, UInt), Map[String, Int]] {
  let index : Map[(Int, UInt), Map[String, Int]] = Map([])
  for i, block in blocks {
    let key = (block.length, block.weak)
    match index.get(key) {
      Some(hashes) =>
        if !hashes.contains(block.strong) {
          hashes.set(block.strong, i)
        }
      None => index.set(key, Map([(block.strong, i)]))
    }
  }
  index
}

///|
/// Receiver stage. The resulting signature may be sent to the sender.
pub fn signature(
  basis : Bytes,
  block_size? : Int = 2048,
  limits? : Limits = Limits::default(),
) -> Signature raise SyncError {
  check_limits(limits)
  check_size(basis.length(), limits)
  if block_size <= 0 || block_size > 512 * 1024 * 1024 {
    raise InvalidInput("block size must be positive and bounded")
  }
  let count = if basis.is_empty() {
    0
  } else {
    (basis.length() - 1) / block_size + 1
  }
  if count > limits.max_blocks {
    raise LimitExceeded("signature block limit exceeded")
  }
  let blocks : Array[BlockSignature] = []
  let mut offset = 0
  while offset < basis.length() {
    let n = Int::min(block_size, basis.length() - offset)
    let view = basis[offset:offset + n]
    blocks.push({
      offset,
      length: n,
      weak: rolling_checksum(view),
      strong: digest(view),
    })
    offset += n
  }
  {
    block_size,
    basis_length: basis.length(),
    basis_digest: digest(basis[:]),
    index: make_index(blocks),
    blocks,
  }
}

///|
fn matching_block(
  sig : Signature,
  data : Bytes,
  offset : Int,
  length : Int,
  weak : UInt,
) -> BlockSignature? {
  match sig.index.get((length, weak)) {
    None => None
    Some(hashes) => {
      let strong = digest(data[offset:offset + length])
      match hashes.get(strong) {
        Some(i) => Some(sig.blocks[i])
        None => None
      }
    }
  }
}

///|
fn push_operation(
  ops : Array[Operation],
  op : Operation,
  limits : Limits,
) -> Unit raise SyncError {
  match op {
    Copy(offset, length) if !ops.is_empty() =>
      match ops[ops.length() - 1] {
        Copy(previous, n) if previous + n == offset => {
          ops[ops.length() - 1] = Copy(previous, n + length)
          return
        }
        _ => ()
      }
    _ => ()
  }
  if ops.length() >= limits.max_operations {
    raise LimitExceeded("delta operation limit exceeded")
  }
  ops.push(op)
}

///|
/// Sender stage. Deliberately accepts only a signature, not the old file.
/// Scans every byte offset, so insertions do not shift all subsequent matches.
pub fn create_delta(
  sig : Signature,
  updated : Bytes,
  limits? : Limits = Limits::default(),
) -> Delta raise SyncError {
  check_limits(limits)
  check_size(updated.length(), limits)
  check_size(sig.basis_length, limits)
  if sig.blocks.length() > limits.max_blocks {
    raise LimitExceeded("signature block limit exceeded")
  }
  let full = sig.block_size
  let tail = sig.basis_length % full
  let ops : Array[Operation] = []
  let mut i = 0
  let mut literal_start = 0
  let mut full_weak = 0U
  let mut tail_weak = 0U
  let mut reset = true
  while i < updated.length() {
    let have_full = full <= updated.length() - i
    let have_tail = tail > 0 && tail <= updated.length() - i
    if reset {
      if have_full {
        full_weak = rolling_checksum(updated[i:i + full])
      }
      if have_tail {
        tail_weak = rolling_checksum(updated[i:i + tail])
      }
      reset = false
    }
    let found = if have_full {
      matching_block(sig, updated, i, full, full_weak)
    } else {
      None
    }
    let found = match found {
      Some(_) => found
      None if have_tail => matching_block(sig, updated, i, tail, tail_weak)
      None => None
    }
    match found {
      Some(block) => {
        if literal_start < i {
          push_operation(
            ops,
            Literal(updated[literal_start:i].to_owned()),
            limits,
          )
        }
        push_operation(ops, Copy(block.offset, block.length), limits)
        i += block.length
        literal_start = i
        reset = true
      }
      None => {
        if full < updated.length() - i {
          full_weak = roll_checksum(
            full_weak,
            updated[i],
            updated[i + full],
            full,
          )
        }
        if tail > 0 && tail < updated.length() - i {
          tail_weak = roll_checksum(
            tail_weak,
            updated[i],
            updated[i + tail],
            tail,
          )
        }
        i += 1
      }
    }
  }
  if literal_start < updated.length() {
    push_operation(ops, Literal(updated[literal_start:].to_owned()), limits)
  }
  {
    basis_length: sig.basis_length,
    basis_digest: sig.basis_digest,
    output_length: updated.length(),
    output_digest: digest(updated[:]),
    operations: ops,
  }
}

///|
/// Receiver stage. Verifies the complete basis before applying and the complete
/// reconstructed output before returning. SHA-256 is integrity, not sender authentication.
pub fn Delta::matches_basis(
  self : Delta,
  basis : Bytes,
  limits? : Limits = Limits::default(),
) -> Bool raise SyncError {
  check_limits(limits)
  check_size(basis.length(), limits)
  check_size(self.basis_length, limits)
  basis.length() == self.basis_length && digest(basis[:]) == self.basis_digest
}

///|
fn operation_view(
  basis : Bytes,
  op : Operation,
  remaining : Int,
) -> BytesView raise SyncError {
  let view = match op {
    Copy(offset, length) => {
      if offset < 0 ||
        length <= 0 ||
        offset > basis.length() ||
        length > basis.length() - offset {
        raise CorruptData("copy outside basis")
      }
      basis[offset:offset + length]
    }
    Literal(data) => {
      if data.is_empty() {
        raise CorruptData("invalid literal length")
      }
      data[:]
    }
  }
  if view.length() > remaining {
    raise CorruptData("output length exceeded")
  }
  view
}

///|
/// Verifies the reconstructed byte stream without allocating output bytes.
/// Basis and delta remain in memory; this is not a streaming file API.
pub fn verify_delta(
  basis : Bytes,
  delta : Delta,
  limits? : Limits = Limits::default(),
) -> Unit raise SyncError {
  check_limits(limits)
  check_size(delta.output_length, limits)
  if delta.operations.length() > limits.max_operations {
    raise LimitExceeded("delta operation limit exceeded")
  }
  if !delta.matches_basis(basis, limits~) {
    raise CorruptData("basis does not match signature")
  }
  let hash = @sha256.Digest::new()
  let mut length = 0
  for op in delta.operations {
    let view = operation_view(basis, op, delta.output_length - length)
    for b in view {
      hash.write(b)
    }
    length += view.length()
  }
  if length != delta.output_length {
    raise CorruptData("output length mismatch")
  }
  if hash.check_sum() != delta.output_digest {
    raise CorruptData("output checksum mismatch")
  }
}

///|
pub fn apply_delta(
  basis : Bytes,
  delta : Delta,
  limits? : Limits = Limits::default(),
) -> Bytes raise SyncError {
  check_limits(limits)
  check_size(basis.length(), limits)
  check_size(delta.output_length, limits)
  if delta.operations.length() > limits.max_operations {
    raise LimitExceeded("delta operation limit exceeded")
  }
  if !delta.matches_basis(basis, limits~) {
    raise CorruptData("basis does not match signature")
  }
  let out : Array[Byte] = []
  for op in delta.operations {
    for b in operation_view(basis, op, delta.output_length - out.length()) {
      out.push(b)
    }
  }
  if out.length() != delta.output_length {
    raise CorruptData("output length mismatch")
  }
  let result = Bytes::from_array(out[:])
  if digest(result[:]) != delta.output_digest {
    raise CorruptData("output checksum mismatch")
  }
  result
}
