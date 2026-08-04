/// RAR5 encryption KDF, ported from `crypt5.cpp` `SetKey50`/`pbkdf2`.
///
/// Derives the AES-256 key, the file-check (HMAC) key and the password-check
/// value from the password (UTF-8) and 16-byte salt using PBKDF2-HMAC-SHA256
/// with 2^Lg2Count iterations. The reference runs one continuous chain: the
/// key is the function value at `Count` iterations, the hash key at
/// `Count + 16`, and the password check value at `Count + 32`.
library;

import 'dart:convert';

import 'hmac.dart';
import 'sha256.dart';

class Kdf5Result {
  const Kdf5Result(this.key, this.hashKey, this.pswCheckValue);

  /// 32-byte AES-256 key.
  final List<int> key;

  /// 32-byte HMAC key used for the CRC32-MAC of encrypted file data.
  final List<int> hashKey;

  /// 32-byte value XOR-folded into the 8-byte stored password check.
  final List<int> pswCheckValue;
}

/// Folds the 32-byte password check value into the 8-byte stored
/// `PswCheck`, as `SetKey50` does.
List<int> foldPswCheck(List<int> pswCheckValue) {
  final out = List<int>.filled(8, 0);
  for (var i = 0; i < 32; i++) {
    out[i % 8] ^= pswCheckValue[i];
  }
  return out;
}

/// Computes the CRC32-MAC of an encrypted file, as `ConvertHashToMAC`.
///
/// [rawCrc] is the 4-byte little-endian plaintext CRC32 and [hashKey] the
/// 32-byte HMAC key from [Kdf5Result.hashKey]. The result replaces the CRC32
/// stored in the file header when the `FHFL_CRC32` flag doubles as a MAC.
int crc32Mac(List<int> rawCrc, List<int> hashKey) {
  final digest = hmacSha256(hashKey, rawCrc);
  var mac = 0;
  for (var i = 0; i < 32; i++) {
    mac ^= digest[i] << ((i & 3) * 8);
  }
  return mac & 0xFFFFFFFF;
}

Kdf5Result kdf5(String password, List<int> salt, int lg2Count) {
  final count = 1 << lg2Count;
  final pwd = utf8.encode(password);
  final saltData = List<int>.of(salt)
    ..addAll(const <int>[0, 0, 0, 1]);

  final innerCache = Sha256Context();
  final outerCache = Sha256Context();
  var u1 = hmacSha256(pwd, saltData, innerCache, outerCache);
  final fn = List<int>.of(u1);

  void chain(int iterations) {
    for (var j = 0; j < iterations; j++) {
      u1 = hmacSha256(pwd, u1, innerCache, outerCache);
      for (var k = 0; k < 32; k++) {
        fn[k] ^= u1[k];
      }
    }
  }

  chain(count - 1);
  final key = List<int>.of(fn);
  chain(16);
  final hashKey = List<int>.of(fn);
  chain(16);
  final pswCheckValue = List<int>.of(fn);
  return Kdf5Result(key, hashKey, pswCheckValue);
}
