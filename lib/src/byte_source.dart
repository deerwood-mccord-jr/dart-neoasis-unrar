import 'dart:typed_data';

/// Abstraction over a byte source, keeping the core library free of
/// `dart:io` so it runs on any platform including the web.
abstract interface class ByteSource {
  /// Reads up to [length] bytes from the current position and advances the
  /// position by the number of bytes actually returned (0 at end of source).
  Future<Uint8List> read(int length);

  /// Moves the read position to [position].
  Future<void> seek(int position);

  /// Returns the current read position.
  Future<int> position();

  /// Returns the total length of the source in bytes.
  Future<int> length();

  /// Releases any underlying resources.
  Future<void> close();
}

/// A [ByteSource] backed by an in-memory buffer, useful for tests.
class MemoryByteSource implements ByteSource {
  MemoryByteSource(this._bytes);

  final Uint8List _bytes;
  int _pos = 0;

  @override
  Future<Uint8List> read(int length) async {
    if (_pos >= _bytes.length) {
      return Uint8List(0);
    }
    final end = (_pos + length).clamp(0, _bytes.length);
    final result = Uint8List.fromList(_bytes.sublist(_pos, end));
    _pos = end;
    return result;
  }

  @override
  Future<void> seek(int position) async {
    _pos = position;
  }

  @override
  Future<int> position() async => _pos;

  @override
  Future<int> length() async => _bytes.length;

  @override
  Future<void> close() async {}
}
