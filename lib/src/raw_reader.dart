import 'dart:typed_data';

import 'byte_source.dart';
import 'aes.dart';
import 'crc.dart';
import 'raw_int.dart';

/// Sequential byte reader with an internal growable buffer, ported from the
/// RARLAB UnRAR `RawRead` class (`rawread.cpp`).
///
/// Data is appended from a [ByteSource] in chunks; individual fields are then
/// pulled out with the `get*` methods. Fields read past the end of buffered
/// data return zero, matching the C implementation.
///
/// When [decryptor] is supplied, bytes read from the [ByteSource] are decrypted
/// (AES-128 or AES-256 CBC) before being appended to the buffer, mirroring
/// `RawRead::SetCrypt`.
///
/// **Performance:** the internal buffer uses a [Uint8List]-backed growable
/// chunk list to avoid boxing every byte as a `List<int>`.
class RawReader {
  RawReader(this._source, {AesCbcDecryptor? decryptor})
      : _decryptor = decryptor;

  final ByteSource _source;
  final AesCbcDecryptor? _decryptor;

  /// List of byte chunks appended by [read]. The logical buffer is the
  /// concatenation of all chunks; [_dataSize] tracks the total and
  /// [_flatCache] is invalidated whenever a new chunk is added.
  final List<Uint8List> _chunks = [];
  int _dataSize = 0;
  int _readPos = 0;

  /// Lazily-built flat view of all chunks. Rebuilt when [_flatDirty] is true.
  Uint8List _flatCache = Uint8List(0);
  bool _flatDirty = false;

  /// Returns the flat (concatenated) view of all buffered data.
  Uint8List get _flat {
    if (!_flatDirty && _flatCache.length == _dataSize) return _flatCache;
    _flatCache = Uint8List(_dataSize);
    var off = 0;
    for (final c in _chunks) {
      _flatCache.setRange(off, off + c.length, c);
      off += c.length;
    }
    _flatDirty = false;
    return _flatCache;
  }

  void _appendChunk(Uint8List chunk) {
    _chunks.add(chunk);
    _dataSize += chunk.length;
    _flatDirty = true;
  }

  // Legacy accessor used by getCRC15 / getCRC50 — returns a view.
  List<int> get data => _flat;

  /// Number of bytes currently buffered.
  int get size => _dataSize;

  /// Current read position within the buffered data.
  int get readPos => _readPos;

  /// Number of buffered bytes not yet consumed.
  int get dataLeft => _dataSize - _readPos;

  void reset() {
    _chunks.clear();
    _flatCache = Uint8List(0);
    _flatDirty = false;
    _readPos = 0;
    _dataSize = 0;
  }

  /// Reads up to [size] bytes from the source into the buffer, matching
  /// `RawRead::Read(size_t)`. When a [decryptor] is set, the read size is
  /// rounded UP to the next 16-byte multiple before reading from the source;
  /// all decrypted bytes are buffered. This mirrors `RawRead::Read` with
  /// `SetCrypt` in the RARLAB source (`rawread.cpp`).
  Future<int> read(int size) async {
    if (size <= 0) return 0;
    // Round up to AES block boundary when decrypting.
    final toRead = _decryptor != null ? ((size + 15) & ~15) : size;
    final bytes = await _source.read(toRead);
    if (bytes.isEmpty) return 0;
    final decrypted = _decryptor != null ? _decryptor.decrypt(bytes) : bytes;
    final chunk = decrypted is Uint8List
        ? decrypted
        : Uint8List.fromList(decrypted);
    _appendChunk(chunk);
    // Report back only `size` bytes so callers see the requested size.
    return chunk.length < size ? chunk.length : size;
  }

  /// Appends an in-memory chunk, matching `RawRead::Read(byte*, size_t)`.
  void readInto(List<int> srcData) {
    if (srcData.isEmpty) return;
    final chunk =
        srcData is Uint8List ? srcData : Uint8List.fromList(srcData);
    _appendChunk(chunk);
  }

  /// Moves unread data to the start of the buffer, matching `Compact`.
  void compact() {
    if (_readPos > 0) {
      final remaining = _flat.sublist(_readPos);
      _chunks.clear();
      _flatCache = remaining;
      _chunks.add(remaining);
      _dataSize = remaining.length;
      _readPos = 0;
      _flatDirty = false;
    }
  }


  /// Reads one byte, matching `Get1`.
  int get1() {
    if (_readPos < _dataSize) return _flat[_readPos++];
    return 0;
  }

  /// Reads two little-endian bytes, matching `Get2`.
  int get2() {
    if (_readPos + 1 < _dataSize) {
      final d = _flat;
      final result = d[_readPos] + (d[_readPos + 1] << 8);
      _readPos += 2;
      return result;
    }
    return 0;
  }

  /// Reads four little-endian bytes, matching `Get4`.
  int get4() {
    if (_readPos + 3 < _dataSize) {
      final result = rawGet4(_flat, _readPos);
      _readPos += 4;
      return result;
    }
    return 0;
  }

  /// Reads eight little-endian bytes, matching `Get8`.
  int get8() {
    final low = get4();
    final high = get4();
    return ((high << 32) | low) & 0xFFFFFFFFFFFFFFFF;
  }

  /// Reads a variable-length integer, matching `GetV`. Returns 0 if the
  /// buffer is exhausted before the terminating byte.
  int getV() {
    final d = _flat;
    var result = 0;
    for (var shift = 0; _readPos < _dataSize && shift < 64; shift += 7) {
      final curByte = d[_readPos++];
      result += ((curByte & 0x7f) << shift);
      if ((curByte & 0x80) == 0) return result;
    }
    return 0;
  }

  /// Returns the number of bytes in the variable-length integer starting at
  /// [pos], matching `GetVSize`. Returns 0 on overflow.
  int getVSize(int pos) {
    final d = _flat;
    for (var curPos = pos; curPos < _dataSize; curPos++) {
      if ((d[curPos] & 0x80) == 0) return curPos - pos + 1;
    }
    return 0;
  }

  /// Copies [size] bytes into a new [Uint8List], zero-filling any shortage,
  /// matching `GetB`.
  Uint8List getB(int size) {
    final copySize = size < dataLeft ? size : dataLeft;
    final out = Uint8List(size);
    final d = _flat;
    out.setRange(0, copySize, d, _readPos);
    _readPos += copySize;
    return out;
  }

  /// Computes the RAR 1.5 - 4.x block CRC, matching `GetCRC15`.
  int getCRC15({bool processedOnly = false}) {
    if (_dataSize <= 2) return 0;
    final end = processedOnly ? _readPos : _dataSize;
    final headerCrc = crc32(0xffffffff, _flat, 2, end - 2);
    return (~headerCrc) & 0xffff;
  }

  /// Computes the RAR 5.0 block CRC, matching `GetCRC50`.
  ///
  /// If [upTo] is provided, only bytes 4..[upTo] are included (used when the
  /// buffer may contain AES-CBC zero-padding beyond the logical header end).
  int getCRC50({int? upTo}) {
    final end = upTo ?? _dataSize;
    if (end <= 4) return 0xffffffff;
    final crc = crc32(0xffffffff, _flat, 4, end - 4);
    return crc ^ 0xffffffff;
  }

  /// Advances the read position by [size] bytes.
  void skip(int size) => _readPos += size;

  /// Sets the read position.
  void setPos(int pos) => _readPos = pos;

  /// Rewinds the read position to the start.
  void rewind() => _readPos = 0;
}

/// Reads a variable-length integer from an arbitrary byte array, matching
/// `RawGetV`.
int rawGetV(List<int> data, int dataSize, int startPos,
    {required void Function() onOverflow}) {
  var readPos = startPos;
  var result = 0;
  for (var shift = 0; readPos < dataSize; shift += 7) {
    final curByte = data[readPos++];
    result += ((curByte & 0x7f) << shift);
    if ((curByte & 0x80) == 0) return result;
  }
  onOverflow();
  return 0;
}
