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
    final result = Uint8List.sublistView(_bytes, _pos, end);
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

// ---------------------------------------------------------------------------
// Synchronous variant
// ---------------------------------------------------------------------------

/// A purely synchronous counterpart to [ByteSource] — no `Future` anywhere in
/// its surface, so it can be driven from ordinary (non-`async`) Dart code.
///
/// Exists for exactly one reason: some callers (a synchronous callback API
/// they don't control, e.g. a drag-and-drop virtual-file provider invoked on
/// a platform-managed thread) genuinely cannot `await`. [MemorySyncByteSource]
/// is the only implementation — reading an in-memory buffer has no real I/O
/// to wait on regardless of whether the surrounding API is `async` or not, so
/// giving it a truly synchronous interface costs nothing and unlocks a
/// synchronous archive-reading path ([SyncArchiveReader]) for that case.
/// There is deliberately no disk-backed synchronous [ByteSource] — reading a
/// real file synchronously on a platform thread that must not block is a
/// different, riskier trade-off than reading bytes already in memory.
abstract interface class SyncByteSource {
  /// Reads up to [length] bytes from the current position and advances the
  /// position by the number of bytes actually returned (0 at end of source).
  Uint8List read(int length);

  /// Moves the read position to [position].
  void seek(int position);

  /// Returns the current read position.
  int position();

  /// Returns the total length of the source in bytes.
  int length();

  /// Releases any underlying resources.
  void close();
}

/// A [SyncByteSource] backed by an in-memory buffer — the synchronous twin
/// of [MemoryByteSource], sharing the exact same semantics.
class MemorySyncByteSource implements SyncByteSource {
  MemorySyncByteSource(this._bytes);

  final Uint8List _bytes;
  int _pos = 0;

  @override
  Uint8List read(int length) {
    if (_pos >= _bytes.length) {
      return Uint8List(0);
    }
    final end = (_pos + length).clamp(0, _bytes.length);
    final result = Uint8List.sublistView(_bytes, _pos, end);
    _pos = end;
    return result;
  }

  @override
  void seek(int position) {
    _pos = position;
  }

  @override
  int position() => _pos;

  @override
  int length() => _bytes.length;

  @override
  void close() {}
}
