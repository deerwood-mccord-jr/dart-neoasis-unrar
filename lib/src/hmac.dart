/// HMAC-SHA256, matching `crypt5.cpp` `hmac_sha256`.
library;

import 'sha256.dart';

/// Computes HMAC-SHA256 of [data] with the given [key].
///
/// Keys longer than 64 bytes are hashed first (as in the reference). The
/// caller may pass cached first-block contexts for the inner ([inner]) and
/// outer ([outer]) hashes, which `kdf5` uses to avoid re-hashing the padded
/// key on every PBKDF2 iteration. The cache entries are updated in place.
List<int> hmacSha256(List<int> key, List<int> data,
    [Sha256Context? inner, Sha256Context? outer]) {
  var k = key;
  if (k.length > 64) {
    k = sha256(k);
  }
  final ic = _paddedKeyContext(k, 0x36, inner).copy();
  sha256Process(ic, data);
  final innerDigest = sha256Done(ic);
  final oc = _paddedKeyContext(k, 0x5c, outer).copy();
  sha256Process(oc, innerDigest);
  return sha256Done(oc);
}

/// Returns a context that has hashed the 64-byte block of [key] padded with
/// [pad]. If [cache] is non-null it is filled with that context (computed
/// only on the first call) and returned, mirroring the `ICtxOpt`/`RCtxOpt`
/// caching in the reference implementation.
Sha256Context _paddedKeyContext(List<int> key, int pad, Sha256Context? cache) {
  if (cache != null && cache.count != 0) {
    return cache;
  }
  final block = List<int>.filled(64, pad);
  for (var i = 0; i < key.length; i++) {
    block[i] = key[i] ^ pad;
  }
  final ctx = Sha256Context();
  sha256Process(ctx, block);
  if (cache != null) {
    for (var i = 0; i < 8; i++) {
      cache.h[i] = ctx.h[i];
    }
    for (var i = 0; i < 64; i++) {
      cache.buffer[i] = ctx.buffer[i];
    }
    cache.count = ctx.count;
  }
  return cache ?? ctx;
}
