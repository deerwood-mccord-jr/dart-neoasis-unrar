import 'dart:typed_data';

import 'byte_source.dart';
import 'crc.dart';
import 'header_constants.dart';
import 'unpack5.dart';
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
/// Method 0 (stored) and the RAR 5.0/7.0 decompressor ([Rar5Unpacker]) are
/// implemented. The RAR 4.x (LZSS/PPMd) decompressors are a future
/// milestone; [Unpacker.unpack] throws [UnsupportedMethodException] for
/// anything else.
class Unpacker {
  Unpacker(this._source);

  final ByteSource _source;

  /// Persistent RAR 5.0/7.0 decompressor, so the window and match history
  /// carry across the files of a solid stream. Recreated never; each entry
  /// passes its own `solid` flag to control state reuse.
  Rar5Unpacker? _rar5;

  /// Unpacks the file whose packed data starts at [dataOffset] in [ByteSource]
  /// and returns the unpacked bytes.
  ///
  /// When [expectedCrc] is non-zero the unpacked data is verified against it
  /// and a [UnrarException] is thrown on mismatch.
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
  }) async {
    if (method == 0) {
      return _store(packSize, unpSize, unknownUnpSize, dataOffset, expectedCrc);
    }
    if (unpVer == verPack5 || unpVer == verPack7) {
      return _unpack5(packSize, unpSize, unknownUnpSize, dataOffset,
          expectedCrc, windowSize, solid, unpVer);
    }
    throw UnsupportedMethodException(method, packSize, unpSize);
  }

  /// Method 0: the packed data is stored verbatim (matching
  /// `CmdExtract::UnstoreFile`), capped at the unpacked size.
  Future<Uint8List> _store(
    int packSize,
    int unpSize,
    bool unknownUnpSize,
    int dataOffset,
    int expectedCrc,
  ) async {
    await _source.seek(dataOffset);
    final packed = await _readUpTo(packSize);
    final out = (!unknownUnpSize && packed.length > unpSize)
        ? Uint8List.sublistView(packed, 0, unpSize)
        : packed;

    if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for stored entry (expected '
            '$expectedCrc, got $actualCrc)');
      }
    }
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
    int unpVer,
  ) async {
    await _source.seek(dataOffset);
    final packed = await _readUpTo(packSize);
    final rar5 = _rar5 ??= Rar5Unpacker();
    final out = rar5.unpack5(
      packed: packed,
      unpSize: unpSize,
      windowSize: windowSize,
      solid: solid,
      extraDist: unpVer == verPack7,
    );

    if (expectedCrc != 0) {
      final actualCrc = crc32Of(out);
      if (actualCrc != expectedCrc) {
        throw UnrarException(
            'CRC32 mismatch for compressed entry (expected '
            '$expectedCrc, got $actualCrc)');
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
