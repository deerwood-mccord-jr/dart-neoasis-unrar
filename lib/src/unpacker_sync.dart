import 'dart:typed_data';

import 'aes.dart';
import 'archive_entry.dart';
import 'bit_input.dart';
import 'byte_source.dart';
import 'header_constants.dart';
import 'hmac.dart';
import 'kdf3.dart';
import 'kdf5.dart';
import 'unpack4.dart';
import 'unpack5.dart';
import 'unpack15.dart';
import 'unpack_output.dart';
import 'unpacker.dart' show UnsupportedMethodException;
import 'unrar_error.dart';

/// Synchronous twin of [Unpacker] — same decompression orchestration, driven
/// by a [SyncByteSource] instead of a [ByteSource]. See [SyncByteSource]'s
/// doc comment for why: the actual decompressors ([Rar5Unpacker],
/// [Rar4Unpacker], [Rar15Unpacker]) are already pure in-memory computation
/// with no `async` anywhere in them — only the handful of `_source.seek`/
/// `read` calls here needed a non-`Future` source to make the whole call
/// chain genuinely synchronous.
class SyncUnpacker {
  SyncUnpacker(this._source);

  final SyncByteSource _source;

  /// Persistent RAR 5.0/7.0 decompressor, so the window and match history
  /// carry across the files of a solid stream. Recreated never; each entry
  /// passes its own `solid` flag to control state reuse.
  Rar5Unpacker? _rar5;

  /// Persistent RAR 4.x decompressor, reused across a solid stream.
  Rar4Unpacker? _rar4;

  /// Persistent RAR 1.5 decompressor, reused across a solid stream.
  Rar15Unpacker? _rar15;

  String? _kdf5Password;
  List<int>? _kdf5Salt;
  int? _kdf5Lg2Count;
  Kdf5Result? _kdf5Result;

  Kdf5Result _deriveKdf5(String password, CryptInfo cryptInfo) {
    final cachedSalt = _kdf5Salt;
    if (_kdf5Result != null &&
        _kdf5Password == password &&
        _kdf5Lg2Count == cryptInfo.lg2Count &&
        cachedSalt != null &&
        _bytesEqual(cachedSalt, cryptInfo.salt)) {
      return _kdf5Result!;
    }
    final result = kdf5(password, cryptInfo.salt, cryptInfo.lg2Count);
    _kdf5Password = password;
    _kdf5Salt = List<int>.of(cryptInfo.salt);
    _kdf5Lg2Count = cryptInfo.lg2Count;
    _kdf5Result = result;
    return result;
  }

  void clearSensitiveState() {
    final result = _kdf5Result;
    if (result != null) {
      result.key.fillRange(0, result.key.length, 0);
      result.hashKey.fillRange(0, result.hashKey.length, 0);
      result.pswCheckValue.fillRange(0, result.pswCheckValue.length, 0);
    }
    _kdf5Salt?.fillRange(0, _kdf5Salt!.length, 0);
    _kdf5Password = null;
    _kdf5Salt = null;
    _kdf5Lg2Count = null;
    _kdf5Result = null;
  }

  UnpackOutput _newOutput(int unpSize, bool unknownUnpSize, bool collectOutput,
          FileHashType hashType) =>
      UnpackOutput(
        expectedSize: unknownUnpSize ? null : unpSize,
        collect: collectOutput,
        computeBlake2: hashType == FileHashType.blake2,
      );

  UnpackResult _collectStored(
    Uint8List data, {
    required int unpSize,
    required bool unknownUnpSize,
    required bool collectOutput,
    required FileHashType hashType,
  }) {
    final output = _newOutput(unpSize, unknownUnpSize, collectOutput, hashType);
    output.add(data);
    return output.finish();
  }

  /// Unpacks the file whose packed data starts at [dataOffset] in
  /// [SyncByteSource] and returns the unpacked bytes. See [Unpacker.unpack]
  /// for the full contract this mirrors.
  Uint8List unpack({
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
    bool collectOutput = true,
  }) {
    if (method == 0) {
      return _store(packSize, unpSize, unknownUnpSize, dataOffset, expectedCrc,
          password: password,
          cryptInfo: cryptInfo,
          hashType: hashType,
          blake2Digest: blake2Digest,
          collectOutput: collectOutput);
    }
    if (unpVer == verPack5 || unpVer == verPack7) {
      return _unpack5(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, windowSize, solid, unpVer,
          password: password,
          cryptInfo: cryptInfo,
          hashType: hashType,
          blake2Digest: blake2Digest,
          collectOutput: collectOutput);
    }
    if (unpVer == 20 || unpVer == 26 || unpVer == 29) {
      return _unpack4(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, windowSize, solid, unpVer,
          password: password,
          cryptInfo: cryptInfo,
          hashType: hashType,
          blake2Digest: blake2Digest,
          collectOutput: collectOutput);
    }
    if (unpVer == 10 || unpVer == 13 || unpVer == 15) {
      return _unpack15(
          packSize, unpSize, unknownUnpSize, dataOffset, expectedCrc, solid,
          password: password,
          cryptInfo: cryptInfo,
          collectOutput: collectOutput);
    }
    throw UnsupportedMethodException(method, packSize, unpSize);
  }

  /// Public wrapper around [_decryptPacked] — kept even though the sync
  /// path has no multi-volume caller today, for parity with [Unpacker].
  Uint8List decryptPacked(Uint8List packed, String password,
          CryptInfo cryptInfo, int expectedCrc) =>
      _decryptPacked(packed, password, cryptInfo, expectedCrc);

  Uint8List _decryptPacked(
      Uint8List packed, String password, CryptInfo cryptInfo, int expectedCrc) {
    if (cryptInfo.isRar4) {
      return _decryptRar4(packed, password, cryptInfo);
    } else {
      return _decryptRar5(packed, password, cryptInfo, expectedCrc);
    }
  }

  Uint8List _decryptRar4(
      Uint8List packed, String password, CryptInfo cryptInfo) {
    final kdf = kdf3(password, cryptInfo.salt);
    final dec =
        AesCbcDecryptor(Aes.withKey(Uint8List.fromList(kdf.key)), kdf.init);
    return dec.decrypt(packed);
  }

  Uint8List _decryptRar5(
      Uint8List packed, String password, CryptInfo cryptInfo, int expectedCrc) {
    final kdf = _deriveKdf5(password, cryptInfo);
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
    return dec.decrypt(packed);
  }

  void _verifyEncryptedCrc(
      int actualCrc, CryptInfo cryptInfo, String password, int storedMac) {
    if (!cryptInfo.useHashKey) {
      return;
    }
    if (storedMac == 0) {
      return;
    }
    final kdf = _deriveKdf5(password, cryptInfo);
    final rawCrc = [
      actualCrc & 0xff,
      (actualCrc >> 8) & 0xff,
      (actualCrc >> 16) & 0xff,
      (actualCrc >> 24) & 0xff,
    ];
    final mac = crc32Mac(rawCrc, kdf.hashKey);
    if (mac != storedMac) {
      throw UnrarException('MAC mismatch for encrypted entry (expected '
          '${storedMac.toRadixString(16)}, got ${mac.toRadixString(16)})');
    }
  }

  void _verifyFileHash(Uint8List? digest, FileHashType hashType,
      List<int>? blake2Digest, CryptInfo? cryptInfo, String? password) {
    if (hashType != FileHashType.blake2 || blake2Digest == null) {
      return;
    }
    if (digest == null) {
      throw StateError('BLAKE2 digest was requested but not computed');
    }
    final expected = blake2Digest;
    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      final kdf = _deriveKdf5(password, cryptInfo);
      final mac = hmacSha256(kdf.hashKey, digest);
      if (!_bytesEqual(mac, expected)) {
        throw UnrarException('BLAKE2 MAC mismatch for encrypted entry '
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
  Uint8List _store(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc, {
    String? password,
    CryptInfo? cryptInfo,
    FileHashType hashType = FileHashType.none,
    List<int>? blake2Digest,
    bool collectOutput = true,
  }) {
    _source.seek(dataOffset);
    var packed = _readUpTo(packSize);
    if (cryptInfo != null && password != null) {
      packed = _decryptPacked(packed, password, cryptInfo, expectedCrc);
    }
    final out = (!unknownUnpSize && packed.length > unpSize)
        ? Uint8List.sublistView(packed, 0, unpSize)
        : packed;
    final result = _collectStored(
      out,
      unpSize: unpSize,
      unknownUnpSize: unknownUnpSize,
      collectOutput: collectOutput,
      hashType: hashType,
    );

    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      _verifyEncryptedCrc(result.crc32, cryptInfo, password, expectedCrc);
    } else if (expectedCrc != 0) {
      final actualCrc = result.crc32;
      if (actualCrc != expectedCrc) {
        throw UnrarException('CRC32 mismatch for stored entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(
        result.blake2Digest, hashType, blake2Digest, cryptInfo, password);
    return result.bytes ?? Uint8List(0);
  }

  /// RAR 5.0/7.0 compressed entry (methods 1-7).
  Uint8List _unpack5(
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
    bool collectOutput = true,
  }) {
    _source.seek(dataOffset);
    var packed = _readUpToPadded(packSize);
    if (cryptInfo != null && password != null) {
      packed = PaddedInput.copyOf(
          _decryptPacked(packed.data, password, cryptInfo, expectedCrc));
    }
    final rar5 = _rar5 ??= Rar5Unpacker();
    final out = rar5.unpack5(
      packed: packed,
      output: _newOutput(unpSize, unknownUnpSize, collectOutput, hashType),
      unpSize: unpSize,
      windowSize: windowSize,
      solid: solid,
      extraDist: unpVer == verPack7,
    );

    if (cryptInfo != null && password != null && cryptInfo.useHashKey) {
      _verifyEncryptedCrc(out.crc32, cryptInfo, password, expectedCrc);
    } else if (expectedCrc != 0) {
      final actualCrc = out.crc32;
      if (actualCrc != expectedCrc) {
        throw UnrarException('CRC32 mismatch for compressed entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(
        out.blake2Digest, hashType, blake2Digest, cryptInfo, password);
    return out.bytes ?? Uint8List(0);
  }

  /// RAR 4.x compressed entry (unpVer 20/26/29).
  Uint8List _unpack4(
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
    bool collectOutput = true,
  }) {
    _source.seek(dataOffset);
    var packed = _readUpToPadded(packSize);
    if (cryptInfo != null && password != null) {
      packed = PaddedInput.copyOf(
          _decryptPacked(packed.data, password, cryptInfo, expectedCrc));
    }
    final rar4 = _rar4 ??= Rar4Unpacker();
    final out = rar4.unpack4(
      packed: packed,
      output: _newOutput(unpSize, unknownUnpSize, collectOutput, hashType),
      unpSize: unpSize,
      windowSize: windowSize,
      solid: solid,
      unpVer: unpVer,
    );

    if (expectedCrc != 0) {
      final actualCrc = out.crc32;
      if (actualCrc != expectedCrc) {
        throw UnrarException('CRC32 mismatch for compressed entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
    _verifyFileHash(
        out.blake2Digest, hashType, blake2Digest, cryptInfo, password);
    return out.bytes ?? Uint8List(0);
  }

  /// RAR 1.5 compressed entry (unpVer 10/13/15).
  Uint8List _unpack15(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc,
    bool solid, {
    String? password,
    CryptInfo? cryptInfo,
    bool collectOutput = true,
  }) {
    _source.seek(dataOffset);
    var packed = _readUpToPadded(packSize);
    if (cryptInfo != null && password != null) {
      packed = PaddedInput.copyOf(
          _decryptPacked(packed.data, password, cryptInfo, expectedCrc));
    }
    final rar15 = _rar15 ??= Rar15Unpacker();
    final out = rar15.unpack15(
        packed: packed,
        output: _newOutput(
            unpSize, unknownUnpSize, collectOutput, FileHashType.none),
        unpSize: unpSize,
        solid: solid);
    if (expectedCrc != 0) {
      final actualCrc = out.crc32;
      if (actualCrc != expectedCrc) {
        throw UnrarException('CRC32 mismatch for RAR 1.5 entry '
            '(expected $expectedCrc, got $actualCrc)');
      }
    }
    return out.bytes ?? Uint8List(0);
  }

  Uint8List _readUpTo(int size) {
    final buffer = Uint8List(size);
    var written = 0;
    while (written < size) {
      final chunk = _source.read(size - written);
      if (chunk.isEmpty) {
        break;
      }
      final copyLength =
          chunk.length > size - written ? size - written : chunk.length;
      buffer.setRange(written, written + copyLength, chunk);
      written += copyLength;
    }
    return written == size ? buffer : Uint8List.sublistView(buffer, 0, written);
  }

  PaddedInput _readUpToPadded(int size) {
    final buffer = Uint8List(size + PaddedInput.paddingSize);
    var written = 0;
    while (written < size) {
      final chunk = _source.read(size - written);
      if (chunk.isEmpty) {
        break;
      }
      final copyLength =
          chunk.length > size - written ? size - written : chunk.length;
      buffer.setRange(written, written + copyLength, chunk);
      written += copyLength;
    }
    return PaddedInput(buffer, written);
  }
}
