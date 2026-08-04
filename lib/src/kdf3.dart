/// RAR3 encryption KDF, ported from `crypt3.cpp` `SetKey30`.
///
/// Derives the AES-128 key and CBC initial vector from a password (encoded as
/// UTF-16LE raw bytes, low byte first) and an optional 8-byte salt, using
/// 0x40000 SHA-1 rounds with the `sha1_process_rar29` variant. The AESInit
/// bytes are the low byte of the digest `e` word at every 16384th round; the
/// AESKey bytes are the little-endian bytes of the four final digest words.
library;

import 'sha1.dart';

class Kdf3Result {
  const Kdf3Result(this.key, this.init);

  /// 16-byte AES-128 key.
  final List<int> key;

  /// 16-byte CBC initial vector.
  final List<int> init;
}

const int _hashRounds = 0x40000;

Kdf3Result kdf3(String password, [List<int>? salt]) {
  final units = password.codeUnits;
  final rawLength = 2 * units.length + (salt?.length ?? 0);
  final raw = List<int>.filled(rawLength, 0);
  for (var i = 0; i < units.length; i++) {
    raw[2 * i] = units[i] & 0xff;
    raw[2 * i + 1] = (units[i] >> 8) & 0xff;
  }
  if (salt != null) {
    raw.setRange(2 * units.length, rawLength, salt);
  }

  final ctx = Sha1Context();
  const snap = _hashRounds ~/ 16;
  final init = List<int>.filled(16, 0);
  final counter = List<int>.filled(3, 0);
  for (var i = 0; i < _hashRounds; i++) {
    sha1ProcessRar29(ctx, raw);
    counter[0] = i & 0xff;
    counter[1] = (i >> 8) & 0xff;
    counter[2] = (i >> 16) & 0xff;
    sha1Process(ctx, counter, 0, 3);
    if (i % snap == 0) {
      final digest = sha1DoneWords(ctx.copy());
      init[i ~/ snap] = digest[4] & 0xff;
    }
  }

  final digest = sha1DoneWords(ctx);
  final key = List<int>.filled(16, 0);
  for (var i = 0; i < 4; i++) {
    for (var j = 0; j < 4; j++) {
      key[i * 4 + j] = (digest[i] >> (j * 8)) & 0xff;
    }
  }
  return Kdf3Result(key, init);
}
