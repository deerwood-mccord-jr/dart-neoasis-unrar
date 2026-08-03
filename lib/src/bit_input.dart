import 'dart:typed_data';

import 'raw_int.dart';

/// Bit-level input reader, ported from the RARLAB UnRAR source
/// (`getbits.hpp` / `getbits.cpp`).
///
/// Reads MSB-first bits from a fixed 32 KiB buffer that must be refilled
/// externally via [buffer].
class BitInput {
  static const int maxSize = 0x8000;

  final Uint8List _buffer;

  int _inAddr = 0; // Current byte position in the buffer.
  int _inBit = 0; // Current bit position in the current byte.

  BitInput() : _buffer = Uint8List(maxSize + 8);

  /// Wraps a fully-loaded compressed stream so the decoder can read it
  /// directly, without the fixed 32 KiB refill loop (mirrors the C
  /// `SetExternalBuffer` mode used by the multi-threaded unpacker).
  ///
  /// Extra zero bytes are appended so the 64-bit readers can over-read
  /// safely at the end of the stream even for tiny or damaged blocks.
  BitInput.external(Uint8List data)
      : _buffer = _padExternal(data);

  static Uint8List _padExternal(Uint8List data) {
    final padded = Uint8List(data.length + 16);
    padded.setRange(0, data.length, data);
    return padded;
  }

  /// The input buffer. Compressed data is loaded into this buffer before
  /// reading bits; 8 extra bytes are kept zeroed so the 64-bit readers can
  /// over-read safely, mirroring the C constructor.
  Uint8List get buffer => _buffer;

  int get inAddr => _inAddr;

  int get inBit => _inBit;

  /// Resets the read position, matching `InitBitInput()`.
  void initBitInput() {
    _inAddr = 0;
    _inBit = 0;
  }

  /// Moves forward by [bits] bits, matching `addbits`.
  void addbits(int bits) {
    bits += _inBit;
    _inAddr += bits >> 3;
    _inBit = bits & 7;
  }

  /// Returns 16 bits from the current position, matching `getbits()`.
  /// The bit at (`_inAddr`, `_inBit`) has the highest position.
  int getbits() {
    final bitField = (_buffer[_inAddr] << 16) |
        (_buffer[_inAddr + 1] << 8) |
        _buffer[_inAddr + 2];
    return (bitField >> (8 - _inBit)) & 0xffff;
  }

  /// Returns 32 bits from the current position, matching `getbits32()`.
  int getbits32() {
    var bitField = rawGetBe4(_buffer, _inAddr);
    bitField = (bitField << _inBit) & 0xFFFFFFFF;
    bitField |= (_buffer[_inAddr + 4] >> (8 - _inBit));
    return bitField & 0xFFFFFFFF;
  }

  /// Returns 64 bits from the current position, matching `getbits64()`.
  int getbits64() {
    var bitField = rawGetBe8(_buffer, _inAddr);
    bitField = (bitField << _inBit) & 0xFFFFFFFFFFFFFFFF;
    bitField |= (_buffer[_inAddr + 8] >> (8 - _inBit));
    return bitField & 0xFFFFFFFFFFFFFFFF;
  }

  /// Returns `true` if the buffer needs refilling before advancing
  /// [incPtr] bytes, matching `Overflow`.
  bool overflow(int incPtr) => _inAddr + incPtr >= maxSize;
}
