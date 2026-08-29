/// BLAKE2sp (parallel BLAKE2s, parallelism 8) as used by RAR 5.0 file
/// hashing (`FHEXTRA_HASH`), ported from the RARLAB sources
/// (`blake2s.cpp` + `blake2sp.cpp`).
///
/// RAR stores a 32-byte digest of the unpacked file in the header extra
/// area. The digest is a BLAKE2sp tree hash: the input is split into 8
/// interleaved 64-byte streams (leaf nodes), each hashed with BLAKE2s using
/// the BLAKE2sp parameter block, and the 8 leaf digests are fed through a
/// root node. The single-threaded path of the reference produces identical
/// output to its multi-threaded path, so this port implements the
/// sequential version directly.
library;

import 'dart:typed_data';

/// BLAKE2s digest size in bytes (also the root inner digest size).
const int blake2DigestSize = 32;

/// Block size in bytes (BLAKE2S_BLOCKBYTES).
const int _blockBytes = 64;

/// Number of parallel leaf chains (PARALLELISM_DEGREE).
const int _parallelism = 8;

const List<int> _iv = [
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const List<List<int>> _sigma = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

int _u32(int x) => x & 0xFFFFFFFF;

int _rotr32(int x, int n) => _u32((x >>> n) | (x << (32 - n)));

int _readLe32(List<int> b, int o) =>
    b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);

void _writeLe32(List<int> b, int o, int v) {
  b[o] = v & 0xff;
  b[o + 1] = (v >> 8) & 0xff;
  b[o + 2] = (v >> 16) & 0xff;
  b[o + 3] = (v >> 24) & 0xff;
}

/// A single BLAKE2s compression state (mirrors `blake2s_state`).
class _Blake2sState {
  _Blake2sState();

  final List<int> h = List<int>.filled(8, 0);
  final List<int> t = List<int>.filled(2, 0);
  final List<int> f = List<int>.filled(2, 0);

  /// Two-block buffer (128 bytes).
  final Uint8List buf = Uint8List(2 * _blockBytes);

  int buflen = 0;
  bool lastNode = false;
}

/// Initialises a state with the BLAKE2sp parameter block, xoring the IV
/// with the digest/key/fanout/depth/node metadata (see `blake2s_init_param`).
void _initParam(_Blake2sState s, int nodeOffset, int nodeDepth) {
  for (var i = 0; i < 8; i++) {
    s.h[i] = _iv[i];
  }
  s.h[0] ^= 0x02080020; // digest 32, no key, fanout 2, depth 8 (BLAKE2sp).
  s.h[2] ^= nodeOffset;
  s.h[3] ^= (nodeDepth << 16) | 0x20000000; // inner digest 32.
}

void _compress(_Blake2sState s, List<int> block) {
  final m = List<int>.filled(16, 0);
  for (var i = 0; i < 16; i++) {
    m[i] = _readLe32(block, i * 4);
  }
  final v = List<int>.filled(16, 0);
  for (var i = 0; i < 8; i++) {
    v[i] = s.h[i];
  }
  v[8] = _iv[0];
  v[9] = _iv[1];
  v[10] = _iv[2];
  v[11] = _iv[3];
  v[12] = _u32(s.t[0] ^ _iv[4]);
  v[13] = _u32(s.t[1] ^ _iv[5]);
  v[14] = _u32(s.f[0] ^ _iv[6]);
  v[15] = _u32(s.f[1] ^ _iv[7]);

  for (var r = 0; r <= 9; r++) {
    _g(r, 0, m, v, 0, 4, 8, 12);
    _g(r, 1, m, v, 1, 5, 9, 13);
    _g(r, 2, m, v, 2, 6, 10, 14);
    _g(r, 3, m, v, 3, 7, 11, 15);
    _g(r, 4, m, v, 0, 5, 10, 15);
    _g(r, 5, m, v, 1, 6, 11, 12);
    _g(r, 6, m, v, 2, 7, 8, 13);
    _g(r, 7, m, v, 3, 4, 9, 14);
  }

  for (var i = 0; i < 8; i++) {
    s.h[i] = _u32(s.h[i] ^ v[i] ^ v[i + 8]);
  }
}

/// One BLAKE2s mixing round (the `G` macro): `a = v[ai]` etc.
void _g(int r, int i, List<int> m, List<int> v, int ai, int bi, int ci, int di) {
  final x = _sigma[r][2 * i];
  final y = _sigma[r][2 * i + 1];
  v[ai] = _u32(v[ai] + v[bi] + m[x]);
  v[di] = _rotr32(v[di] ^ v[ai], 16);
  v[ci] = _u32(v[ci] + v[di]);
  v[bi] = _rotr32(v[bi] ^ v[ci], 12);
  v[ai] = _u32(v[ai] + v[bi] + m[y]);
  v[di] = _rotr32(v[di] ^ v[ai], 8);
  v[ci] = _u32(v[ci] + v[di]);
  v[bi] = _rotr32(v[bi] ^ v[ci], 7);
}

void _incrementCounter(_Blake2sState s, int inc) {
  s.t[0] = _u32(s.t[0] + inc);
  s.t[1] = _u32(s.t[1] + (s.t[0] < inc ? 1 : 0));
}

/// Feeds [inLen] bytes of [input] starting at [inPos] into [s].
void _update(_Blake2sState s, List<int> input, int inLen, [int inPos = 0]) {
  while (inLen > 0) {
    final left = s.buflen;
    final fill = 2 * _blockBytes - left;
    if (inLen > fill) {
      s.buf.setRange(left, left + fill, input, inPos);
      s.buflen += fill;
      _incrementCounter(s, _blockBytes);
      _compress(s, s.buf);
      // Shift the second block into place.
      for (var i = 0; i < _blockBytes; i++) {
        s.buf[i] = s.buf[i + _blockBytes];
      }
      s.buflen -= _blockBytes;
      inPos += fill;
      inLen -= fill;
    } else {
      s.buf.setRange(left, left + inLen, input, inPos);
      s.buflen += inLen;
      inPos += inLen;
      inLen = 0;
    }
  }
}

void _finalize(_Blake2sState s, List<int> digest) {
  if (s.buflen > _blockBytes) {
    _incrementCounter(s, _blockBytes);
    _compress(s, s.buf);
    s.buflen -= _blockBytes;
    for (var i = 0; i < s.buflen; i++) {
      s.buf[i] = s.buf[i + _blockBytes];
    }
  }
  _incrementCounter(s, s.buflen);
  if (s.lastNode) {
    s.f[1] = 0xFFFFFFFF;
  }
  s.f[0] = 0xFFFFFFFF;
  // Zero-pad the final block (mirrors the `memset` in `blake2s_final`).
  for (var i = s.buflen; i < 2 * _blockBytes; i++) {
    s.buf[i] = 0;
  }
  _compress(s, s.buf);
  for (var i = 0; i < 8; i++) {
    _writeLe32(digest, i * 4, s.h[i]);
  }
}

/// Incremental BLAKE2sp hasher (RAR variant). Mirrors `blake2sp_state` with
/// the 8 leaf chains and the root state; call [update] any number of times
/// then [finalize].
class Blake2Sp {
  Blake2Sp() {
    _root = _Blake2sState();
    _initParam(_root, 0, 1); // Root node, depth 1.
    _root.lastNode = true;
    _leaves = List.generate(_parallelism, (i) {
      final s = _Blake2sState();
      _initParam(s, i, 0); // Leaf node.
      return s;
    });
    _leaves[_parallelism - 1].lastNode = true;
  }

  late final _Blake2sState _root;
  late final List<_Blake2sState> _leaves;
  final Uint8List _buf = Uint8List(_parallelism * _blockBytes);
  int _buflen = 0;

  /// Feeds [data] into the tree hash.
  void update(List<int> data, [int offset = 0, int? length]) {
    var inPos = offset;
    var inLen = length ?? data.length - offset;
    var left = _buflen;
    final fill = _buf.length - left;
    if (left != 0 && inLen >= fill) {
      _buf.setRange(left, left + fill, data, inPos);
      for (var i = 0; i < _parallelism; i++) {
        _update(_leaves[i], _buf, _blockBytes, i * _blockBytes);
      }
      inPos += fill;
      inLen -= fill;
      left = 0;
    }
    // Feed full 512-byte rounds: block i of each round goes to leaf i.
    final rounds = inLen ~/ (_parallelism * _blockBytes);
    for (var i = 0; i < _parallelism; i++) {
      final leaf = _leaves[i];
      final base = inPos + i * _blockBytes;
      for (var k = 0; k < rounds; k++) {
        _update(leaf, data, _blockBytes, base + k * (_parallelism * _blockBytes));
      }
    }
    inPos += rounds * (_parallelism * _blockBytes);
    inLen -= rounds * (_parallelism * _blockBytes);
    if (inLen > 0) {
      _buf.setRange(left, left + inLen, data, inPos);
    }
    _buflen = left + inLen;
  }

  /// Computes and returns the 32-byte BLAKE2sp digest.
  Uint8List finalize() {
    final hash = List.generate(
        _parallelism, (_) => Uint8List(blake2DigestSize), growable: false);
    for (var i = 0; i < _parallelism; i++) {
      if (_buflen > i * _blockBytes) {
        var tail = _buflen - i * _blockBytes;
        if (tail > _blockBytes) {
          tail = _blockBytes;
        }
        _update(_leaves[i], _buf, tail, i * _blockBytes);
      }
      _finalize(_leaves[i], hash[i]);
    }
    for (var i = 0; i < _parallelism; i++) {
      _update(_root, hash[i], blake2DigestSize);
    }
    final digest = Uint8List(blake2DigestSize);
    _finalize(_root, digest);
    return digest;
  }

  /// One-shot convenience: BLAKE2sp digest of [data].
  static Uint8List digest(List<int> data) {
    final h = Blake2Sp()..update(data);
    return h.finalize();
  }
}
