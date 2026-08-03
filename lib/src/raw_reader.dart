import 'byte_source.dart';
import 'crc.dart';
import 'raw_int.dart';

/// Sequential byte reader with an internal growable buffer, ported from the
/// RARLAB UnRAR `RawRead` class (`rawread.cpp`).
///
/// Data is appended from a [ByteSource] in chunks; individual fields are then
/// pulled out with the `get*` methods. Fields read past the end of buffered
/// data return zero, matching the C implementation.
class RawReader {
  RawReader(this._source);

  final ByteSource _source;

  final List<int> _data = [];
  int _dataSize = 0;
  int _readPos = 0;

  /// Number of bytes currently buffered.
  int get size => _dataSize;

  /// Current read position within the buffered data.
  int get readPos => _readPos;

  /// Number of buffered bytes not yet consumed.
  int get dataLeft => _dataSize - _readPos;

  /// The raw buffer contents.
  List<int> get data => _data;

  void reset() {
    _data.clear();
    _readPos = 0;
    _dataSize = 0;
  }

  /// Reads up to [size] bytes from the source into the buffer, matching
  /// `RawRead::Read(size_t)`.
  Future<int> read(int size) async {
    if (size <= 0) {
      return 0;
    }
    final bytes = await _source.read(size);
    if (bytes.isEmpty) {
      return 0;
    }
    _data.addAll(bytes);
    _dataSize += bytes.length;
    return bytes.length;
  }

  /// Appends an in-memory chunk, matching `RawRead::Read(byte*, size_t)`.
  void readInto(List<int> srcData) {
    if (srcData.isEmpty) {
      return;
    }
    _data.addAll(srcData);
    _dataSize += srcData.length;
  }

  /// Moves unread data to the start of the buffer, matching `Compact`.
  void compact() {
    if (_readPos < _dataSize) {
      for (var i = _readPos; i < _dataSize; i++) {
        _data[i - _readPos] = _data[i];
      }
    }
    _dataSize -= _readPos;
    _readPos = 0;
    _data.length = _dataSize;
  }

  /// Reads one byte, matching `Get1`.
  int get1() => _readPos < _dataSize ? _data[_readPos++] : 0;

  /// Reads two little-endian bytes, matching `Get2`.
  int get2() {
    if (_readPos + 1 < _dataSize) {
      final result = _data[_readPos] + (_data[_readPos + 1] << 8);
      _readPos += 2;
      return result;
    }
    return 0;
  }

  /// Reads four little-endian bytes, matching `Get4`.
  int get4() {
    if (_readPos + 3 < _dataSize) {
      final result = rawGet4(_data, _readPos);
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
    var result = 0;
    for (var shift = 0; _readPos < _dataSize && shift < 64; shift += 7) {
      final curByte = _data[_readPos++];
      result += ((curByte & 0x7f) << shift);
      if ((curByte & 0x80) == 0) {
        return result;
      }
    }
    return 0;
  }

  /// Returns the number of bytes in the variable-length integer starting at
  /// [pos], matching `GetVSize`. Returns 0 on overflow.
  int getVSize(int pos) {
    for (var curPos = pos; curPos < _dataSize; curPos++) {
      if ((_data[curPos] & 0x80) == 0) {
        return curPos - pos + 1;
      }
    }
    return 0;
  }

  /// Copies [size] bytes into a new list, zero-filling any shortage,
  /// matching `GetB`.
  List<int> getB(int size) {
    final copySize = size < dataLeft ? size : dataLeft;
    final out = List<int>.filled(size, 0);
    for (var i = 0; i < copySize; i++) {
      out[i] = _data[_readPos + i];
    }
    _readPos += copySize;
    return out;
  }

  /// Computes the RAR 1.5 - 4.x block CRC, matching `GetCRC15`.
  int getCRC15({bool processedOnly = false}) {
    if (_dataSize <= 2) {
      return 0;
    }
    final end = processedOnly ? _readPos : _dataSize;
    final headerCrc = crc32(0xffffffff, _data, 2, end - 2);
    return (~headerCrc) & 0xffff;
  }

  /// Computes the RAR 5.0 block CRC, matching `GetCRC50`.
  int getCRC50() {
    if (_dataSize <= 4) {
      return 0xffffffff;
    }
    final crc = crc32(0xffffffff, _data, 4, _dataSize - 4);
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
    if ((curByte & 0x80) == 0) {
      return result;
    }
  }
  onOverflow();
  return 0;
}
