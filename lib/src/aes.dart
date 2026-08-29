/// AES (Rijndael) block cipher, ported from the RARLAB UnRAR source
/// (`rijndael.cpp`). Supports 128/192/256-bit keys.
///
/// The RAR encryption uses AES in CBC mode with a stateful IV that persists
/// across reads; `AesCbcDecryptor` models that (`Rijndael::m_initVector`).
library;

import 'dart:typed_data';

const List<int> _sbox = <int>[
  0x63,
  0x7c,
  0x77,
  0x7b,
  0xf2,
  0x6b,
  0x6f,
  0xc5,
  0x30,
  0x01,
  0x67,
  0x2b,
  0xfe,
  0xd7,
  0xab,
  0x76,
  0xca,
  0x82,
  0xc9,
  0x7d,
  0xfa,
  0x59,
  0x47,
  0xf0,
  0xad,
  0xd4,
  0xa2,
  0xaf,
  0x9c,
  0xa4,
  0x72,
  0xc0,
  0xb7,
  0xfd,
  0x93,
  0x26,
  0x36,
  0x3f,
  0xf7,
  0xcc,
  0x34,
  0xa5,
  0xe5,
  0xf1,
  0x71,
  0xd8,
  0x31,
  0x15,
  0x04,
  0xc7,
  0x23,
  0xc3,
  0x18,
  0x96,
  0x05,
  0x9a,
  0x07,
  0x12,
  0x80,
  0xe2,
  0xeb,
  0x27,
  0xb2,
  0x75,
  0x09,
  0x83,
  0x2c,
  0x1a,
  0x1b,
  0x6e,
  0x5a,
  0xa0,
  0x52,
  0x3b,
  0xd6,
  0xb3,
  0x29,
  0xe3,
  0x2f,
  0x84,
  0x53,
  0xd1,
  0x00,
  0xed,
  0x20,
  0xfc,
  0xb1,
  0x5b,
  0x6a,
  0xcb,
  0xbe,
  0x39,
  0x4a,
  0x4c,
  0x58,
  0xcf,
  0xd0,
  0xef,
  0xaa,
  0xfb,
  0x43,
  0x4d,
  0x33,
  0x85,
  0x45,
  0xf9,
  0x02,
  0x7f,
  0x50,
  0x3c,
  0x9f,
  0xa8,
  0x51,
  0xa3,
  0x40,
  0x8f,
  0x92,
  0x9d,
  0x38,
  0xf5,
  0xbc,
  0xb6,
  0xda,
  0x21,
  0x10,
  0xff,
  0xf3,
  0xd2,
  0xcd,
  0x0c,
  0x13,
  0xec,
  0x5f,
  0x97,
  0x44,
  0x17,
  0xc4,
  0xa7,
  0x7e,
  0x3d,
  0x64,
  0x5d,
  0x19,
  0x73,
  0x60,
  0x81,
  0x4f,
  0xdc,
  0x22,
  0x2a,
  0x90,
  0x88,
  0x46,
  0xee,
  0xb8,
  0x14,
  0xde,
  0x5e,
  0x0b,
  0xdb,
  0xe0,
  0x32,
  0x3a,
  0x0a,
  0x49,
  0x06,
  0x24,
  0x5c,
  0xc2,
  0xd3,
  0xac,
  0x62,
  0x91,
  0x95,
  0xe4,
  0x79,
  0xe7,
  0xc8,
  0x37,
  0x6d,
  0x8d,
  0xd5,
  0x4e,
  0xa9,
  0x6c,
  0x56,
  0xf4,
  0xea,
  0x65,
  0x7a,
  0xae,
  0x08,
  0xba,
  0x78,
  0x25,
  0x2e,
  0x1c,
  0xa6,
  0xb4,
  0xc6,
  0xe8,
  0xdd,
  0x74,
  0x1f,
  0x4b,
  0xbd,
  0x8b,
  0x8a,
  0x70,
  0x3e,
  0xb5,
  0x66,
  0x48,
  0x03,
  0xf6,
  0x0e,
  0x61,
  0x35,
  0x57,
  0xb9,
  0x86,
  0xc1,
  0x1d,
  0x9e,
  0xe1,
  0xf8,
  0x98,
  0x11,
  0x69,
  0xd9,
  0x8e,
  0x94,
  0x9b,
  0x1e,
  0x87,
  0xe9,
  0xce,
  0x55,
  0x28,
  0xdf,
  0x8c,
  0xa1,
  0x89,
  0x0d,
  0xbf,
  0xe6,
  0x42,
  0x68,
  0x41,
  0x99,
  0x2d,
  0x0f,
  0xb0,
  0x54,
  0xbb,
  0x16,
];

List<int> _inverseSbox() {
  final inv = List<int>.filled(256, 0);
  for (var i = 0; i < 256; i++) {
    inv[_sbox[i]] = i;
  }
  return inv;
}

final List<int> _invSbox = _inverseSbox();

const List<int> _rcon = <int>[
  0x01,
  0x02,
  0x04,
  0x08,
  0x10,
  0x20,
  0x40,
  0x80,
  0x1b,
  0x36,
];

int _xtime(int x) => ((x << 1) ^ ((x & 0x80) != 0 ? 0x1b : 0)) & 0xff;

int _gfmul(int a, int b) {
  var r = 0;
  var p = a & 0xff;
  var q = b & 0xff;
  while (q != 0) {
    if ((q & 1) != 0) {
      r ^= p;
    }
    p = _xtime(p);
    q >>= 1;
  }
  return r & 0xff;
}

class Aes {
  /// Expanded key schedule, stored big-endian (byte 0 of each word first).
  final List<int> _rk;
  final int _nr;

  Aes._(this._rk, this._nr);

  factory Aes.withKey(List<int> key) {
    final nk = key.length ~/ 4;
    final nr = nk + 6;
    final totalWords = 4 * (nr + 1);
    final rk = List<int>.filled(totalWords * 4, 0);
    for (var i = 0; i < key.length; i++) {
      rk[i] = key[i];
    }
    final word = List<int>.filled(totalWords, 0);
    for (var i = 0; i < nk; i++) {
      word[i] = (key[i * 4] << 24) |
          (key[i * 4 + 1] << 16) |
          (key[i * 4 + 2] << 8) |
          key[i * 4 + 3];
    }
    var temp = 0;
    for (var i = nk; i < totalWords; i++) {
      temp = word[i - 1];
      if (i % nk == 0) {
        // RotWord + SubWord + Rcon.
        temp = ((_sbox[(temp >> 16) & 0xff] << 24) |
                (_sbox[(temp >> 8) & 0xff] << 16) |
                (_sbox[temp & 0xff] << 8) |
                _sbox[(temp >> 24) & 0xff]) ^
            (_rcon[i ~/ nk - 1] << 24);
      } else if (nk > 6 && i % nk == 4) {
        temp = (_sbox[(temp >> 24) & 0xff] << 24) |
            (_sbox[(temp >> 16) & 0xff] << 16) |
            (_sbox[(temp >> 8) & 0xff] << 8) |
            _sbox[temp & 0xff];
      }
      word[i] = word[i - nk] ^ temp;
      final o = i * 4;
      rk[o] = (word[i] >> 24) & 0xff;
      rk[o + 1] = (word[i] >> 16) & 0xff;
      rk[o + 2] = (word[i] >> 8) & 0xff;
      rk[o + 3] = word[i] & 0xff;
    }
    return Aes._(rk, nr);
  }

  void _addRoundKey(List<int> s, int round) {
    final base = round * 16;
    for (var c = 0; c < 4; c++) {
      final o = base + c * 4;
      s[c * 4] ^= _rk[o];
      s[c * 4 + 1] ^= _rk[o + 1];
      s[c * 4 + 2] ^= _rk[o + 2];
      s[c * 4 + 3] ^= _rk[o + 3];
    }
  }

  void _subBytes(List<int> s) {
    for (var i = 0; i < 16; i++) {
      s[i] = _sbox[s[i]];
    }
  }

  void _invSubBytes(List<int> s) {
    for (var i = 0; i < 16; i++) {
      s[i] = _invSbox[s[i]];
    }
  }

  void _shiftRows(List<int> s) {
    final t = List<int>.filled(16, 0);
    t[0] = s[0];
    t[1] = s[5];
    t[2] = s[10];
    t[3] = s[15];
    t[4] = s[4];
    t[5] = s[9];
    t[6] = s[14];
    t[7] = s[3];
    t[8] = s[8];
    t[9] = s[13];
    t[10] = s[2];
    t[11] = s[7];
    t[12] = s[12];
    t[13] = s[1];
    t[14] = s[6];
    t[15] = s[11];
    for (var i = 0; i < 16; i++) {
      s[i] = t[i];
    }
  }

  void _invShiftRows(List<int> s) {
    final t = List<int>.filled(16, 0);
    t[0] = s[0];
    t[1] = s[13];
    t[2] = s[10];
    t[3] = s[7];
    t[4] = s[4];
    t[5] = s[1];
    t[6] = s[14];
    t[7] = s[11];
    t[8] = s[8];
    t[9] = s[5];
    t[10] = s[2];
    t[11] = s[15];
    t[12] = s[12];
    t[13] = s[9];
    t[14] = s[6];
    t[15] = s[3];
    for (var i = 0; i < 16; i++) {
      s[i] = t[i];
    }
  }

  void _mixColumns(List<int> s) {
    for (var c = 0; c < 4; c++) {
      final o = c * 4;
      final s0 = s[o];
      final s1 = s[o + 1];
      final s2 = s[o + 2];
      final s3 = s[o + 3];
      s[o] = _gfmul(s0, 2) ^ _gfmul(s1, 3) ^ s2 ^ s3;
      s[o + 1] = s0 ^ _gfmul(s1, 2) ^ _gfmul(s2, 3) ^ s3;
      s[o + 2] = s0 ^ s1 ^ _gfmul(s2, 2) ^ _gfmul(s3, 3);
      s[o + 3] = _gfmul(s0, 3) ^ s1 ^ s2 ^ _gfmul(s3, 2);
    }
  }

  void _invMixColumns(List<int> s) {
    for (var c = 0; c < 4; c++) {
      final o = c * 4;
      final s0 = s[o];
      final s1 = s[o + 1];
      final s2 = s[o + 2];
      final s3 = s[o + 3];
      s[o] = _gfmul(s0, 14) ^ _gfmul(s1, 11) ^ _gfmul(s2, 13) ^ _gfmul(s3, 9);
      s[o + 1] =
          _gfmul(s0, 9) ^ _gfmul(s1, 14) ^ _gfmul(s2, 11) ^ _gfmul(s3, 13);
      s[o + 2] =
          _gfmul(s0, 13) ^ _gfmul(s1, 9) ^ _gfmul(s2, 14) ^ _gfmul(s3, 11);
      s[o + 3] =
          _gfmul(s0, 11) ^ _gfmul(s1, 13) ^ _gfmul(s2, 9) ^ _gfmul(s3, 14);
    }
  }

  /// Encrypts the 16-byte block in place.
  void encryptBlock(List<int> block) {
    _addRoundKey(block, 0);
    for (var round = 1; round < _nr; round++) {
      _subBytes(block);
      _shiftRows(block);
      _mixColumns(block);
      _addRoundKey(block, round);
    }
    _subBytes(block);
    _shiftRows(block);
    _addRoundKey(block, _nr);
  }

  /// Decrypts the 16-byte block in place.
  void decryptBlock(List<int> block) {
    _addRoundKey(block, _nr);
    for (var round = _nr - 1; round > 0; round--) {
      _invShiftRows(block);
      _invSubBytes(block);
      _addRoundKey(block, round);
      _invMixColumns(block);
    }
    _invShiftRows(block);
    _invSubBytes(block);
    _addRoundKey(block, 0);
  }
}

/// Stateful AES-CBC decryptor. The IV persists across [decrypt] calls, as in
/// the RARLAB `Rijndael` (which keeps the last ciphertext block as
/// `m_initVector` and is called repeatedly by `UnpRead`/`ReadHeader15`).
class AesCbcDecryptor {
  AesCbcDecryptor(this._aes, List<int> iv) : _iv = List<int>.of(iv);

  final Aes _aes;
  final List<int> _iv;

  Uint8List decrypt(List<int> data) {
    if (data.isEmpty) return Uint8List(0);
    final n = data.length ~/ 16;
    final out = Uint8List(n * 16);
    final ct = Uint8List(16);
    for (var b = 0; b < n; b++) {
      final o = b * 16;
      for (var j = 0; j < 16; j++) {
        ct[j] = data[o + j];
      }
      _aes.decryptBlock(ct);
      for (var j = 0; j < 16; j++) {
        out[o + j] = ct[j] ^ _iv[j];
      }
      for (var j = 0; j < 16; j++) {
        _iv[j] = data[o + j];
      }
    }
    return out;
  }

  List<int> get iv => List<int>.of(_iv);

  /// The underlying [Aes] cipher (key schedule). Exposed so callers can
  /// create a new [AesCbcDecryptor] with a different IV but the same key,
  /// as RAR 5.0 encrypted-header archives do for each header block.
  Aes get aes => _aes;
}
