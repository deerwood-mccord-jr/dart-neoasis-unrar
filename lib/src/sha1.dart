/// SHA-1 implementation ported from the RARLAB UnRAR source (`sha1.cpp`).
///
/// This includes `sha1_process_rar29`, the non-standard variant used by the
/// RAR3 encryption KDF (`crypt3.cpp` `SetKey30`). It differs from the standard
/// SHA-1 only in that, after hashing every full 64-byte block after the first,
/// the 16 message-schedule words are written back into the input buffer as
/// little-endian bytes. Because `SetKey30` reuses one persistent password
/// buffer across all 0x40000 rounds, later rounds hash the mutated bytes.
library;

class Sha1Context {
  Sha1Context();

  final List<int> state =
      List<int>.from(<int>[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
  final List<int> buffer = List<int>.filled(64, 0);
  int count = 0;

  Sha1Context copy() {
    final c = Sha1Context();
    for (var i = 0; i < 5; i++) {
      c.state[i] = state[i];
    }
    for (var i = 0; i < 64; i++) {
      c.buffer[i] = buffer[i];
    }
    c.count = count;
    return c;
  }

  void _reset() {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
    count = 0;
  }
}

int _rotl(int x, int n) => ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF;

/// Reads 16 big-endian words from [src] starting at [offset].
List<int> _toWords(List<int> src, int offset) {
  final w = List<int>.filled(16, 0);
  for (var i = 0; i < 16; i++) {
    final o = offset + i * 4;
    w[i] = (src[o] << 24) | (src[o + 1] << 16) | (src[o + 2] << 8) | src[o + 3];
  }
  return w;
}

/// Hashes a single 512-bit block. [w] holds the 16 initial words (already
/// byte-swapped to big-endian interpretation) and is mutated in place as the
/// message schedule is expanded, mirroring `SHA1Transform`.
void _transform(List<int> state, List<int> w) {
  var a = state[0];
  var b = state[1];
  var c = state[2];
  var d = state[3];
  var e = state[4];
  for (var i = 0; i < 80; i++) {
    int f;
    int k;
    if (i < 20) {
      f = ((b & (c ^ d)) ^ d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = ((b | c) & d) | (b & c);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    if (i >= 16) {
      w[i & 15] = _rotl(
          w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15], 1);
    }
    final t = (_rotl(a, 5) + f + e + k + w[i & 15]) & 0xFFFFFFFF;
    e = d;
    d = c;
    c = _rotl(b, 30);
    b = a;
    a = t;
  }
  state[0] = (state[0] + a) & 0xFFFFFFFF;
  state[1] = (state[1] + b) & 0xFFFFFFFF;
  state[2] = (state[2] + c) & 0xFFFFFFFF;
  state[3] = (state[3] + d) & 0xFFFFFFFF;
  state[4] = (state[4] + e) & 0xFFFFFFFF;
}

/// Streaming `sha1_process`.
void sha1Process(Sha1Context ctx, List<int> data, [int offset = 0, int? length]) {
  final len = length ?? data.length - offset;
  var j = ctx.count & 63;
  ctx.count += len;
  var pos = offset;
  if ((j + len) > 63) {
    final i = 64 - j;
    for (var k = 0; k < i; k++) {
      ctx.buffer[j + k] = data[pos + k];
    }
    _transform(ctx.state, _toWords(ctx.buffer, 0));
    pos += i;
    while (pos + 63 < offset + len) {
      _transform(ctx.state, _toWords(data, pos));
      pos += 64;
    }
    j = 0;
  }
  if (offset + len > pos) {
    final rem = offset + len - pos;
    for (var k = 0; k < rem; k++) {
      ctx.buffer[j + k] = data[pos + k];
    }
  }
}

/// Streaming `sha1_process_rar29`. Mutates [data] in place by writing the
/// message-schedule words of each fully-processed block after the first back
/// into the buffer as little-endian bytes.
void sha1ProcessRar29(Sha1Context ctx, List<int> data,
    [int offset = 0, int? length]) {
  final len = length ?? data.length - offset;
  var j = ctx.count & 63;
  ctx.count += len;
  var pos = offset;
  if ((j + len) > 63) {
    final i = 64 - j;
    for (var k = 0; k < i; k++) {
      ctx.buffer[j + k] = data[pos + k];
    }
    _transform(ctx.state, _toWords(ctx.buffer, 0));
    pos += i;
    while (pos + 63 < offset + len) {
      final w = _toWords(data, pos);
      _transform(ctx.state, w);
      for (var k = 0; k < 16; k++) {
        final v = w[k];
        data[pos + k * 4] = v & 0xff;
        data[pos + k * 4 + 1] = (v >> 8) & 0xff;
        data[pos + k * 4 + 2] = (v >> 16) & 0xff;
        data[pos + k * 4 + 3] = (v >> 24) & 0xff;
      }
      pos += 64;
    }
    j = 0;
  }
  if (offset + len > pos) {
    final rem = offset + len - pos;
    for (var k = 0; k < rem; k++) {
      ctx.buffer[j + k] = data[pos + k];
    }
  }
}

void _writeBe64(List<int> buf, int value) {
  buf[56] = (value >> 56) & 0xff;
  buf[57] = (value >> 48) & 0xff;
  buf[58] = (value >> 40) & 0xff;
  buf[59] = (value >> 32) & 0xff;
  buf[60] = (value >> 24) & 0xff;
  buf[61] = (value >> 16) & 0xff;
  buf[62] = (value >> 8) & 0xff;
  buf[63] = value & 0xff;
}

/// Finishes the hash, resets [ctx], and returns the 5 digest words.
/// Matches `sha1_done`, which yields the state as uint32 words.
List<int> sha1DoneWords(Sha1Context ctx) {
  final bitLength = ctx.count * 8;
  var bufPos = ctx.count & 0x3f;
  ctx.buffer[bufPos++] = 0x80;
  if (bufPos != 56) {
    if (bufPos > 56) {
      while (bufPos < 64) {
        ctx.buffer[bufPos++] = 0;
      }
      bufPos = 0;
    }
    if (bufPos == 0) {
      _transform(ctx.state, _toWords(ctx.buffer, 0));
    }
    while (bufPos < 56) {
      ctx.buffer[bufPos++] = 0;
    }
  }
  _writeBe64(ctx.buffer, bitLength);
  _transform(ctx.state, _toWords(ctx.buffer, 0));
  final digest = List<int>.of(ctx.state);
  ctx._reset();
  return digest;
}

/// Convenience: standard 20-byte SHA-1 digest of [data].
List<int> sha1Bytes(List<int> data) {
  final ctx = Sha1Context();
  sha1Process(ctx, data);
  final words = sha1DoneWords(ctx);
  final out = List<int>.filled(20, 0);
  for (var i = 0; i < 5; i++) {
    out[i * 4] = (words[i] >> 24) & 0xff;
    out[i * 4 + 1] = (words[i] >> 16) & 0xff;
    out[i * 4 + 2] = (words[i] >> 8) & 0xff;
    out[i * 4 + 3] = words[i] & 0xff;
  }
  return out;
}
