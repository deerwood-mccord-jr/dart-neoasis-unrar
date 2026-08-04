/// SHA-256 implementation ported from the RARLAB UnRAR source (`sha256.cpp`).
library;

class Sha256Context {
  Sha256Context();

  final List<int> h = List<int>.from(<int>[
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
  ]);
  final List<int> buffer = List<int>.filled(64, 0);
  int count = 0;

  Sha256Context copy() {
    final c = Sha256Context();
    for (var i = 0; i < 8; i++) {
      c.h[i] = h[i];
    }
    for (var i = 0; i < 64; i++) {
      c.buffer[i] = buffer[i];
    }
    c.count = count;
    return c;
  }

  void _reset() {
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;
    count = 0;
  }
}

const List<int> _k = <int>[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF;

int _s0(int x) => _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22);
int _s1(int x) => _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25);
int _g0(int x) => _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3);
int _g1(int x) => _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10);

void _transform(Sha256Context ctx) {
  final w = List<int>.filled(64, 0);
  final buf = ctx.buffer;
  for (var i = 0; i < 16; i++) {
    final o = i * 4;
    w[i] = (buf[o] << 24) | (buf[o + 1] << 16) | (buf[o + 2] << 8) | buf[o + 3];
  }
  for (var i = 16; i < 64; i++) {
    w[i] = (_g1(w[i - 2]) + w[i - 7] + _g0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF;
  }
  final h = ctx.h;
  var v0 = h[0];
  var v1 = h[1];
  var v2 = h[2];
  var v3 = h[3];
  var v4 = h[4];
  var v5 = h[5];
  var v6 = h[6];
  var v7 = h[7];
  for (var i = 0; i < 64; i++) {
    final t1 = (v7 + _s1(v4) + ((v4 & v5) ^ (~v4 & v6)) + _k[i] + w[i]) & 0xFFFFFFFF;
    final t2 = (_s0(v0) + ((v0 & v1) ^ (v0 & v2) ^ (v1 & v2))) & 0xFFFFFFFF;
    v7 = v6;
    v6 = v5;
    v5 = v4;
    v4 = (v3 + t1) & 0xFFFFFFFF;
    v3 = v2;
    v2 = v1;
    v1 = v0;
    v0 = (t1 + t2) & 0xFFFFFFFF;
  }
  h[0] = (h[0] + v0) & 0xFFFFFFFF;
  h[1] = (h[1] + v1) & 0xFFFFFFFF;
  h[2] = (h[2] + v2) & 0xFFFFFFFF;
  h[3] = (h[3] + v3) & 0xFFFFFFFF;
  h[4] = (h[4] + v4) & 0xFFFFFFFF;
  h[5] = (h[5] + v5) & 0xFFFFFFFF;
  h[6] = (h[6] + v6) & 0xFFFFFFFF;
  h[7] = (h[7] + v7) & 0xFFFFFFFF;
}

/// Streaming `sha256_process`.
void sha256Process(Sha256Context ctx, List<int> data,
    [int offset = 0, int? length]) {
  final total = length ?? data.length - offset;
  final bufPos0 = ctx.count & 0x3f;
  ctx.count += total;
  var bufPos = bufPos0;
  var src = offset;
  var size = total;
  while (size > 0) {
    final bufSpace = 64 - bufPos;
    final copySize = size > bufSpace ? bufSpace : size;
    for (var i = 0; i < copySize; i++) {
      ctx.buffer[bufPos + i] = data[src + i];
    }
    src += copySize;
    bufPos += copySize;
    size -= copySize;
    if (bufPos == 64) {
      bufPos = 0;
      _transform(ctx);
    }
  }
}

/// Finishes the hash, resets [ctx], and returns the 32-byte digest.
List<int> sha256Done(Sha256Context ctx) {
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
      _transform(ctx);
    }
    while (bufPos < 56) {
      ctx.buffer[bufPos++] = 0;
    }
  }
  ctx.buffer[56] = (bitLength >> 56) & 0xff;
  ctx.buffer[57] = (bitLength >> 48) & 0xff;
  ctx.buffer[58] = (bitLength >> 40) & 0xff;
  ctx.buffer[59] = (bitLength >> 32) & 0xff;
  ctx.buffer[60] = (bitLength >> 24) & 0xff;
  ctx.buffer[61] = (bitLength >> 16) & 0xff;
  ctx.buffer[62] = (bitLength >> 8) & 0xff;
  ctx.buffer[63] = bitLength & 0xff;
  _transform(ctx);
  final digest = List<int>.filled(32, 0);
  final h = ctx.h;
  for (var i = 0; i < 8; i++) {
    digest[i * 4] = (h[i] >> 24) & 0xff;
    digest[i * 4 + 1] = (h[i] >> 16) & 0xff;
    digest[i * 4 + 2] = (h[i] >> 8) & 0xff;
    digest[i * 4 + 3] = h[i] & 0xff;
  }
  ctx._reset();
  return digest;
}

/// Convenience: SHA-256 digest of [data].
List<int> sha256(List<int> data) {
  final ctx = Sha256Context();
  sha256Process(ctx, data);
  return sha256Done(ctx);
}
