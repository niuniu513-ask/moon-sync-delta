///|
/// Reuse an existing ecosystem SHA-256 implementation rather than inventing one.
pub fn digest(data : BytesView) -> String {
  let hash = @sha256.Digest::new()
  for b in data {
    hash.write(b)
  }
  hash.check_sum()
}

///|
/// The original rsync unsigned-byte rolling checksum, modulo 2^16.
/// This is a candidate filter, never evidence of byte equality.
pub fn rolling_checksum(data : BytesView) -> UInt {
  let mut a = 0U
  let mut b = 0U
  for value in data {
    a = (a + value.to_uint()) & 0xffffU
    b = (b + a) & 0xffffU
  }
  (b << 16) | a
}

///|
/// Moves a checksum window by one byte in constant time.
pub fn roll_checksum(
  checksum : UInt,
  outgoing : Byte,
  incoming : Byte,
  window : Int,
) -> UInt raise SyncError {
  if window <= 0 || window > 512 * 1024 * 1024 {
    raise InvalidInput("window must be positive and bounded")
  }
  let a = ((checksum & 0xffffU) - outgoing.to_uint() + incoming.to_uint()) &
    0xffffU
  let b = (
      (checksum >> 16) - window.reinterpret_as_uint() * outgoing.to_uint() + a
    ) &
    0xffffU
  (b << 16) | a
}
