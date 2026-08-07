import 'dart:typed_data';

import 'aes.dart';
import 'archive_entry.dart';
import 'blake2s.dart';
import 'byte_source.dart';
import 'crc.dart';
import 'header_constants.dart';
import 'hmac.dart';
import 'kdf3.dart';
import 'kdf5.dart';
import 'unpack4.dart';
import 'unpack5.dart';
import 'unpack15.dart';
import 'unrar_error.dart';

/// The packed data uses a compression method that is not implemented yet.
class UnsupportedMethodException extends UnrarException {
  UnsupportedMethodException(this.method, this.packSize, this.unpSize)
      : super('Compression method $method is not supported yet '
            '(packed $packSize bytes, unpacked $unpSize bytes)');

  /// Raw compression method code from the entry header.
  final int method;

  final int packSize;

  final int unpSize;

  @override
  String toString() => 'UnsupportedMethodException: $message';
}

/// Decompresses a single entry's packed data stream, ported from the C
/// `Unpack` class (`unpack.cpp`).
///
/// Method 0 (stored), the RAR 5.0/7.0 decompressor ([Rar5Unpacker]), the
/// RAR 4.x decompressor ([Rar4Unpacker], unpVer 20/26/29), and the RAR 1.5
/// decompressor ([Rar15Unpacker], unpVer 10/13/15) are all implemented.
class Unpacker {
  Unpacker(this._source);

  final ByteSource _source;

  /// Persistent RAR 5.0/7.0 decompressor, so the window and match history
  /// carry across the files of a solid stream. Recreated never; each entry
  /// passes its own `solid` flag to control state reuse.
  Rar5Unpacker? _rar5;

  /// Persistent RAR 4.x decompressor, reused across a solid stream.
  Rar4Unpacker? _rar4;

  /// Persistent RAR 1.5 decompressor, reused across a solid stream.
  Rar15Unpacker? _rar15;

  /// Unpacks from a pre-assembled [data] buffer (used for multi-volume
  /// entries where packed fragments have already been concatenated and
  /// optionally decrypted by the caller).
  ///
  /// When [alreadyDecrypted] is `true` the buffer is passed directly to the
  /// decompressor; otherwise [password] + [cryptInfo] are applied first.
  Future<Uint8List> unpackFromBuffer({
    required int method,
    required int unpSize,
    required bool unknownUnpSize,
    required int expectedCrc,
    int unpVer = verUnknown,
    int windowSize = 0,
    bool solid = false,
    required Uint8List data,
    String? password,
    CryptInfo? cryptInfo,
    bool alreadyDecrypted = false,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
  }) async {
    Uint8List packed = data;
    if (!alreadyDecrypted && cryptInfo != null && password != null) {
      packed = _decryptPacked(data, password, cryptInfo, expectedCrc);
    }

    if (method == 0) {
      final out = (!unknownUnpSize && packed.length > unpSize)
          ? Uint8List.sublistView(packed, 0, unpSize)
          : packed;
      if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
        _verifyEncryptedCrc(out, cryptInfo, password, expectedCrc);
      } else if (expectedCrc != 0) {
        final actualCrc = crc32Of(out);
        if (actualCrc != expectedCrc) {
          throw UnrarException(
              'CRC32 mismatch for split stored entry '
              '(expected $expectedCrc, got $actualCrc)');
        }
      }
      _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
      return out;
    }

    if (unpVer == verPack5 || unpVer == verPack7) {
      final rar5 = _rar5 ??= Rar5Unpacker();
      final out = rar5.unpack5(
        packed: packed,
        unpSize: unpSize,
        windowSize: windowSize,
        solid: solid,
        extraDist: unpVer == verPack7,
      );
      if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
        _verifyEncryptedCrc(out, cryptInfo, password, expectedCrc);
      } else if (expectedCrc != 0) {
        final actualCrc = crc32Of(out);
        if (actualCrc != expectedCrc) {
          throw UnrarException(
              'CRC32 mismatch for split compressed entry '
              '(expected $expectedCrc, got $actualCrc)');
        }
      }
      _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
      return out;
    }

    if (unpVer == 20 || unpVer == 26 || unpVer == 29) {
      final rar4 = _rar4 ??= Rar4Unpacker();
      final out = rar4.unpack4(
        packed: packed,
        unpSize: unpSize,
        windowSize: windowSize,
        solid: solid,
        unpVer: unpVer,
      );
      if (expectedCrc != 0) {
        final actualCrc = crc32Of(out);
        if (actualCrc != expectedCrc) {
          throw UnrarException(
              'CRC32 mismatch for split compressed entry '
              '(expected $expectedCrc, got $actualCrc)');
        }
      }
      _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
      return out;
    }

    if (unpVer == 10 || unpVer == 13 || unpVer == 15) {
      final rar15 = _rar15 ??= Rar15Unpacker();
      final out = rar15.unpack15(
          packed: packed, unpSize: unpSize, solid: solid);
      if (expectedCrc != 0) {
        final actualCrc = crc32Of(out);
        if (actualCrc != expectedCrc) {
          throw UnrarException(
              'CRC32 mismatch for RAR 1.5 split entry '
              '(expected $expectedCrc, got $actualCrc)');
        }
      }
      return out;
    }

    throw UnsupportedMethodException(method, data.length, unpSize);
  }

  /// Unpacks the file whose packed data starts at [dataOffset] in [ByteSource]
  /// and returns the unpacked bytes.
  ///
  /// When [expectedCrc] is non-zero the unpacked data is verified against it
  /// and a [UnrarException] is thrown on mismatch. When [password] and
  /// [cryptInfo] are supplied the packed data is decrypted before
  /// decompression.
  ///
  /// For RAR 5.0/7.0 compressed entries ([unpVer] 50/70, method 1-7) the full
  /// packed stream is read into memory and passed to [Rar5Unpacker], with
  /// [windowSize] and [solid] controlling the LZ dictionary.
  Future<Uint8List> unpack({
    required int method,
    required int packSize,
    required int unpSize,
    required bool unknownUnpSize,
    required int dataOffset,
    required int expectedCrc,
    int unpVer = verUnknown,
    int windowSize = 0,
    bool solid = false,
    String? password,
    CryptInfo? cryptInfo,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
  }) async {
    if (method == 0) {
      return _store(packSize, unpSize, unknownUnpSize, dataOffset, expectedCrc,
          password: password, cryptInfo: cryptInfo,
          hashType: hashType, blake2Digest: blake2Digest);
    }
    if (unpVer == verPack5 || unpVer == verPack7) {
      return _unpack5(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, windowSize, solid, unpVer,
          password: password, cryptInfo: cryptInfo,
          hashType: hashType, blake2Digest: blake2Digest);
    }
    if (unpVer == 20 || unpVer == 26 || unpVer == 29) {
      return _unpack4(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, windowSize, solid, unpVer,
          password: password, cryptInfo: cryptInfo,
          hashType: hashType, blake2Digest: blake2Digest);
    }
    if (unpVer == 10 || unpVer == 13 || unpVer == 15) {
      return _unpack15(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, solid,
          password: password, cryptInfo: cryptInfo);
    }
    throw UnsupportedMethodException(method, packSize, unpSize);
  }

  /// Public wrapper around [_decryptPacked] used when assembling
  /// multi-volume packed streams before decompression.
  Uint8List decryptPacked(Uint8List packed, String password,
          CryptInfo cryptInfo, int expectedCrc) =>
      _decryptPacked(packed, password, cryptInfo, expectedCrc);

  /// Decrypts [packed] in-place when [cryptInfo] is present.
  ///
  /// RAR 5.0: AES-256-CBC with PBKDF2-derived key. The stream is zero-padded
  /// to a 16-byte boundary; the plaintext trailing padding is harmless because
  /// the unpacker stops at the end-of-stream marker (compressed) or at
  /// [unpSize] (stored). The header's CRC32 field holds an HMAC-SHA256 MAC
  /// when [CryptInfo.useHashKey] is `true`; in that case we compute the MAC
  /// from the CRC32 of the plaintext and compare.
  ///
  /// RAR 4.x: AES-128-CBC with SHA-1 KDF. Same zero-padding model. CRC32 is
  /// plain (not a MAC).
  Uint8List _decryptPacked(Uint8List packed, String password,
      CryptInfo cryptInfo, int expectedCrc) {
    if (cryptInfo.isRar4) {
      return _decryptRar4(packed, password, cryptInfo);
    } else {
      return _decryptRar5(packed, password, cryptInfo, expectedCrc);
    }
  }

  Uint8List _decryptRar4(
      Uint8List packed, String password, CryptInfo cryptInfo) {
    final kdf = kdf3(password, cryptInfo.salt);
    final dec = AesCbcDecryptor(
        Aes.withKey(Uint8List.fromList(kdf.key)), kdf.init);
    return Uint8List.fromList(dec.decrypt(packed));
  }

  Uint8List _decryptRar5(Uint8List packed, String password, CryptInfo cryptInfo,
      int expectedCrc) {
    final kdf = kdf5(password, cryptInfo.salt, cryptInfo.lg2Count);
    // Optionally verify password before expensive decompression.
    if (cryptInfo.usePswCheck && cryptInfo.pswCheck != null) {
      final computed = foldPswCheck(kdf.pswCheckValue);
      for (var i = 0; i < sizePswCheck; i++) {
        if (computed[i] != cryptInfo.pswCheck![i]) {
          throw const UnrarException('Wrong password for encrypted file');
        }
      }
    }
    final dec = AesCbcDecryptor(
        Aes.withKey(Uint8List.fromList(kdf.key)), cryptInfo.iv!);
    return Uint8List.fromList(dec.decrypt(packed));
  }

  /// After extracting plaintext, verifies the integrity of encrypted file data.
  ///
  /// For RAR 5.0 with HMAC-SHA256 MAC ([CryptInfo.useHashKey] = `true`) the
  /// stored "CRC32" in the header is actually `crc32Mac(crc32(plain), hashKey)`
  /// (see `ConvertHashToMAC` in `crypt5.cpp`). We compute the real CRC32,
  /// compute the MAC from it, and compare.
  ///
  /// For plain CRC32 (RAR 4.x and RAR 5.0 without HASHMAC) the comparison is
  /// done by the regular CRC check in `_store`/`_unpack5`/`_unpack4`.
  void _verifyEncryptedCrc(
      Uint8List plain, CryptInfo cryptInfo, String password, int storedMac) {
    if (!cryptInfo.useHashKey) {
      return; // Plain CRC32 — handled by the regular check.
    }
    if (storedMac == 0) {
      return; // No CRC stored (RAR 5: FHFL_CRC32 flag absent); nothing to verify.
    }
    final kdf = kdf5(password, cryptInfo.salt, cryptInfo.lg2Count);
    final actualCrc = crc32Of(plain);
    final rawCrc = [
      actualCrc & 0xff,
      (actualCrc >> 8) & 0xff,
      (actualCrc >> 16) & 0xff,
      (actualCrc >> 24) & 0xff,
    ];
    final mac = crc32Mac(rawCrc, kdf.hashKey);
    if (mac != storedMac) {
      throw UnrarException(
          'MAC mismatch for encrypted entry (expected '
          '${storedMac.toRadixString(16)}, got ${mac.toRadixString(16)})');
    }
  }

  /// Verifies the stored BLAKE2sp digest of the unpacked data when the entry
  /// carries a `FHEXTRA_HASH` record.
  ///
  /// For encrypted RAR 5.0 entries with HMAC ([CryptInfo.useHashKey]) the
  /// stored 32 bytes are `hmacSha256(hashKey, blake2sp(plaintext))` (see
  /// `ConvertHashToMAC` in `crypt5.cpp`); otherwise they are the plain digest.
  void _verifyFileHash(Uint8List plain, FileHashType hashType,
      List<int>? blake2Digest, CryptInfo? cryptInfo, String? password) {
    if (hashType != FileHashType.blake2 || blake2Digest == null) {
      return;
    }
    final digest = Blake2Sp.digest(plain);
    final expected = blake2Digest;
    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      final kdf = kdf5(password, cryptInfo.salt, cryptInfo.lg2Count);
      final mac = hmacSha256(kdf.hashKey, digest);
      if (!_bytesEqual(mac, expected)) {
        throw UnrarException(
            'BLAKE2 MAC mismatch for encrypted entry '
            '(wrong password or corrupt data)');
      }
    } else if (!_bytesEqual(digest, expected)) {
      throw UnrarException('BLAKE2 digest mismatch for entry');
    }
  }

  static bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  /// Method 0: the packed data is stored verbatim (matching
  /// `CmdExtract::UnstoreFile`), capped at the unpacked size.
  Future<Uint8List> _store(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc, {
    String? password,
    CryptInfo? cryptInfo,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
  }) async {
    await _source.seek(dataOffset);
    var packed = await _readUpTo(packSize);
    if (cryptInfo != null && password != null) {
      packed = _decryptPacked(packed, password, cryptInfo, expectedCrc);
    }
    final out = (!unknownUnpSize && packed.length > unpSize)
        ? Uint8List.sublistView(packed, 0, unpSize)
        : packed;

    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      _verifyEncryptedCrc(out, cryptInfo, password, expectedCrc);
    } else if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for stored entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
    return out;
  }

  /// RAR 5.0/7.0 compressed entry (methods 1-7).
  Future<Uint8List> _unpack5(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc,
    int windowSize,
    bool solid,
    int unpVer, {
    String? password,
    CryptInfo? cryptInfo,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
  }) async {
    await _source.seek(dataOffset);
    var packed = await _readUpTo(packSize);
    if (cryptInfo != null && password != null) {
      packed = _decryptPacked(packed, password, cryptInfo, expectedCrc);
    }
    final rar5 = _rar5 ??= Rar5Unpacker();
    final out = rar5.unpack5(
      packed: packed,
      unpSize: unpSize,
      windowSize: windowSize,
      solid: solid,
      extraDist: unpVer == verPack7,
    );

    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      _verifyEncryptedCrc(out, cryptInfo, password, expectedCrc);
    } else if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for compressed entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
    return out;
  }

  /// RAR 4.x compressed entry (unpVer 20/26/29).
  Future<Uint8List> _unpack4(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc,
    int windowSize,
    bool solid,
    int unpVer, {
    String? password,
    CryptInfo? cryptInfo,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
  }) async {
    await _source.seek(dataOffset);
    var packed = await _readUpTo(packSize);
    if (cryptInfo != null && password != null) {
      packed = _decryptPacked(packed, password, cryptInfo, expectedCrc);
    }
    final rar4 = _rar4 ??= Rar4Unpacker();
    final out = rar4.unpack4(
      packed: packed,
      unpSize: unpSize,
      windowSize: windowSize,
      solid: solid,
      unpVer: unpVer,
    );

    if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for compressed entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(out, hashType, blake2Digest, cryptInfo, password);
    return out;
  }

  /// RAR 1.5 compressed entry (unpVer 10/13/15).
  Future<Uint8List> _unpack15(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc,
    bool solid, {
    String? password,
    CryptInfo? cryptInfo,
  }) async {
    await _source.seek(dataOffset);
    var packed = await _readUpTo(packSize);
    if (cryptInfo != null && password != null) {
      packed = _decryptPacked(packed, password, cryptInfo, expectedCrc);
    }
    final rar15 = _rar15 ??= Rar15Unpacker();
    final out = rar15.unpack15(packed: packed, unpSize: unpSize, solid: solid);
    // RAR 1.4/1.5 use Checksum14, not CRC32; expectedCrc is stored as 0
    // for RAR 1.4 entries (no CRC32 stored).  For RAR 1.5 compressed entries
    // the header stores a full CRC32, so verify when non-zero.
    if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for RAR 1.5 entry '
            '(expected $expectedCrc, got $actualCrc)');
      }
    }
    return out;
  }

  Future<Uint8List> _readUpTo(int size) async {
    final buffer = <int>[];
    var remaining = size;
    while (remaining > 0) {
      final chunk = await _source.read(remaining);
      if (chunk.isEmpty) {
        break;
      }
      buffer.addAll(chunk);
      remaining -= chunk.length;
    }
    return Uint8List.fromList(buffer);
  }
}
