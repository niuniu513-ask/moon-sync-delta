///|
/// All failures are explicit; untrusted frames must never cause a bounds panic.
pub suberror SyncError {
  InvalidInput(String)
  CorruptData(String)
  LimitExceeded(String)
} derive(Debug)

///|
pub extend SyncError with @debug.Debug::{to_repr}

///|
pub(all) struct Limits {
  max_bytes : Int
  max_blocks : Int
  max_operations : Int
} derive(Eq, Debug)

///|
pub extend Limits with Eq::{equal, not_equal}

///|
pub extend Limits with @debug.Debug::{to_repr}

///|
pub fn Limits::default() -> Limits {
  { max_bytes: 64 * 1024 * 1024, max_blocks: 100_000, max_operations: 100_000, }
}

///|
fn check_limits(limits : Limits) -> Unit raise SyncError {
  if limits.max_bytes < 0 ||
    limits.max_bytes > 512 * 1024 * 1024 ||
    limits.max_blocks < 0 ||
    limits.max_blocks > 1_000_000 ||
    limits.max_operations < 0 ||
    limits.max_operations > 1_000_000 {
    raise InvalidInput("limits outside supported bounds")
  }
}

///|
fn check_size(size : Int, limits : Limits) -> Unit raise SyncError {
  if size > limits.max_bytes {
    raise LimitExceeded("byte limit exceeded")
  }
}

///|
struct BlockSignature {
  offset : Int
  length : Int
  weak : UInt
  strong : String
}

///|
/// Contains checksums only, never the receiver's original data.
pub struct Signature {
  block_size : Int
  basis_length : Int
  basis_digest : String
  blocks : Array[BlockSignature]
  index : Map[(Int, UInt), Map[String, Int]]
}

///|
pub fn Signature::block_count(self : Signature) -> Int {
  self.blocks.length()
}

///|
pub fn Signature::block_size(self : Signature) -> Int {
  self.block_size
}

///|
pub fn Signature::basis_length(self : Signature) -> Int {
  self.basis_length
}

///|
pub fn Signature::basis_digest(self : Signature) -> String {
  self.basis_digest
}

///|
pub(all) enum Operation {
  Literal(Bytes)
  Copy(Int, Int)
} derive(Eq, Debug)

///|
pub extend Operation with Eq::{equal, not_equal}

///|
pub extend Operation with @debug.Debug::{to_repr}

///|
pub struct Delta {
  basis_length : Int
  basis_digest : String
  output_length : Int
  output_digest : String
  operations : Array[Operation]
}

///|
/// Returns a fresh array so callers cannot change a validated delta.
pub fn Delta::operations(self : Delta) -> Array[Operation] {
  self.operations.copy()
}

///|
pub fn Delta::output_digest(self : Delta) -> String {
  self.output_digest
}

///|
pub(all) struct Statistics {
  output_bytes : Int
  copied_bytes : Int
  literal_bytes : Int
  copy_operations : Int
  literal_operations : Int
  wire_bytes : Int
} derive(Eq, Debug)

///|
pub extend Statistics with Eq::{equal, not_equal}

///|
pub extend Statistics with @debug.Debug::{to_repr}

///|
/// Payload reuse is separate from actual wire savings: headers have a cost.
pub fn Delta::statistics(self : Delta) -> Statistics {
  let mut copied = 0
  let mut literal = 0
  let mut copies = 0
  let mut literals = 0
  let mut wire = 148
  for op in self.operations {
    match op {
      Copy(_, n) => {
        copied += n
        copies += 1
        wire += 9
      }
      Literal(data) => {
        literal += data.length()
        literals += 1
        wire += 5 + data.length()
      }
    }
  }
  {
    output_bytes: self.output_length,
    copied_bytes: copied,
    literal_bytes: literal,
    copy_operations: copies,
    literal_operations: literals,
    wire_bytes: wire,
  }
}

///|
/// Compares actual framed delta bytes plus optional signature cost against the
/// uncompressed full output. This is a size decision, not a throughput prediction.
pub fn Delta::worth_sending(
  self : Delta,
  signature_bytes? : Int = 0,
) -> Bool raise SyncError {
  if signature_bytes < 0 {
    raise InvalidInput("negative signature cost")
  }
  signature_bytes < self.output_length &&
  self.statistics().wire_bytes < self.output_length - signature_bytes
}
