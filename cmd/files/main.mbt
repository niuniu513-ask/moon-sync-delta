///|
// This optional host adapter uses Node.js for file I/O only.
// Signature, matching, framing and verification remain in the MoonBit core.
extern "js" fn read_file(path : String) -> Bytes =
  #| function(path) {
  #|   const fs = require('node:fs');
  #|   const fd = fs.openSync(path, 'r');
  #|   try {
  #|     const stat = fs.fstatSync(fd);
  #|     if (!stat.isFile()) throw new Error('Input must be a regular file');
  #|     const size = stat.size;
  #|     if (size > 64 * 1024 * 1024) throw new Error('Input exceeds 64 MiB');
  #|     const result = Buffer.alloc(size);
  #|     let done = 0;
  #|     while (done < size) {
  #|       const n = fs.readSync(fd, result, done, size - done, null);
  #|       if (n === 0) throw new Error('Input shrank while reading');
  #|       done += n;
  #|     }
  #|     if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null) !== 0) throw new Error('Input grew while reading');
  #|     return result;
  #|   } finally { fs.closeSync(fd); }
  #| }

///|
extern "js" fn write_new_file(path : String, data : Bytes) -> Unit =
  #| function(path, data) {
  #|   require('node:fs').writeFileSync(path, data, {flag: 'wx'});
  #| }

///|
extern "js" fn fail() -> Unit =
  #| function() { process.exitCode = 1; }

///|
priv suberror UsageError {
  UsageError(String)
}

///|
fn run(args : Array[String]) -> Unit raise {
  match args {
    ["signature", source, destination, .. rest] => {
      if rest.length() > 1 {
        raise UsageError("too many arguments")
      }
      let block = if rest.length() == 0 {
        2048
      } else {
        @string.parse_int(rest[0])
      }
      let sig = @sync.signature(read_file(source), block_size=block)
      let wire = @sync.encode_signature(sig)
      write_new_file(destination, wire)
      println(
        "signature: blocks=\{sig.block_count()}, wire_bytes=\{wire.length()}",
      )
    }
    ["delta", signatures, updated, destination] => {
      let signature_wire = read_file(signatures)
      let sig = @sync.decode_signature(signature_wire)
      let delta = @sync.create_delta(sig, read_file(updated))
      let wire = @sync.encode_delta(delta)
      write_new_file(destination, wire)
      let s = delta.statistics()
      let recommendation = if delta.worth_sending(
          signature_bytes=signature_wire.length(),
        ) {
        "delta"
      } else {
        "full"
      }
      println(
        "delta: output=\{s.output_bytes}, reused=\{s.copied_bytes}, literal=\{s.literal_bytes}, wire_bytes=\{wire.length()}, recommend=\{recommendation}",
      )
    }
    ["apply", source, patch, destination] => {
      let delta = @sync.decode_delta(read_file(patch))
      let output = @sync.apply_delta(read_file(source), delta)
      write_new_file(destination, output)
      println(
        "verified: bytes=\{output.length()}, sha256=\{delta.output_digest()}",
      )
    }
    ["inspect", patch] => {
      let delta = @sync.decode_delta(read_file(patch))
      let s = delta.statistics()
      println(
        "output=\{s.output_bytes}, reused=\{s.copied_bytes}, literal=\{s.literal_bytes}, wire_bytes=\{s.wire_bytes}",
      )
    }
    _ =>
      raise UsageError(
        "usage: signature OLD SIG [BLOCK] | delta SIG NEW DELTA | apply OLD DELTA OUTPUT | inspect DELTA",
      )
  }
}

///|
fn main {
  let args = @env.args()
  let cli = if args.length() >= 2 { args[2:].to_owned() } else { [] }
  run(cli) catch {
    error => {
      println("error: \{error}")
      fail()
    }
  }
}
