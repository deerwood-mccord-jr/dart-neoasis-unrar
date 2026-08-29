import 'dart:typed_data';

import 'blake2s.dart';
import 'crc.dart';

/// Final state produced by an [UnpackOutput] sink.
class UnpackResult {
  const UnpackResult({
    required this.bytes,
    required this.length,
    required this.crc32,
    required this.checksum14,
    required this.blake2Digest,
  });

  final Uint8List? bytes;
  final int length;
  final int crc32;
  final int checksum14;
  final Uint8List? blake2Digest;
}

/// Receives final post-filter bytes from an unpacker.
///
/// It mirrors native UnRAR's `ComprDataIO::UnpWrite`: integrity state is
/// updated as bytes are emitted, while collection can be disabled for test
/// mode. Known-size output is written directly into one exact allocation.
class UnpackOutput {
  UnpackOutput({
    required int? expectedSize,
    required bool collect,
    bool computeBlake2 = false,
  })  : _expectedSize = expectedSize,
        _fixed = collect && expectedSize != null
            ? Uint8List(expectedSize)
            : null,
        _chunks = collect && expectedSize == null ? BytesBuilder() : null,
        _blake2 = computeBlake2 ? Blake2Sp() : null;

  final int? _expectedSize;
  final Uint8List? _fixed;
  final BytesBuilder? _chunks;
  final Blake2Sp? _blake2;
  final Uint8List _oneByte = Uint8List(1);

  int _length = 0;
  int _crc = 0xffffffff;
  int _checksum14 = 0;
  bool _finished = false;

  int get length => _length;

  void add(Uint8List data, [int offset = 0, int? length]) {
    if (_finished) {
      throw StateError('Cannot add bytes after output is finished');
    }
    var count = length ?? data.length - offset;
    if (offset < 0 || count < 0 || offset + count > data.length) {
      throw RangeError.range(offset + count, 0, data.length);
    }
    final expected = _expectedSize;
    if (expected != null && count > expected - _length) {
      count = expected - _length;
    }
    if (count <= 0) return;

    final fixed = _fixed;
    if (fixed != null) {
      fixed.setRange(_length, _length + count, data, offset);
    } else {
      _chunks?.add(Uint8List.sublistView(data, offset, offset + count));
    }

    _crc = crc32(_crc, data, offset, count);
    _checksum14 = checksum14(_checksum14, data, offset, count);
    _blake2?.update(data, offset, count);
    _length += count;
  }

  void addByte(int byte) {
    _oneByte[0] = byte;
    add(_oneByte);
  }

  UnpackResult finish() {
    if (_finished) {
      throw StateError('Output is already finished');
    }
    _finished = true;

    Uint8List? bytes;
    final fixed = _fixed;
    if (fixed != null) {
      bytes = _length == fixed.length
          ? fixed
          : Uint8List.sublistView(fixed, 0, _length);
    } else if (_chunks != null) {
      bytes = _chunks.takeBytes();
    }

    return UnpackResult(
      bytes: bytes,
      length: _length,
      crc32: _crc ^ 0xffffffff,
      checksum14: _checksum14,
      blake2Digest: _blake2?.finalize(),
    );
  }
}
