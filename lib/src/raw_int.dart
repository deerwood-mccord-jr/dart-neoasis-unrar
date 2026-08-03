/// Raw little/big-endian integer readers, ported from the RARLAB UnRAR
/// source (`rawint.hpp`).
library;

/// Load 2 little-endian bytes.
int rawGet2(List<int> data, int offset) =>
    data[offset] + (data[offset + 1] << 8);

/// Load 4 little-endian bytes as an unsigned 32-bit value.
int rawGet4(List<int> data, int offset) =>
    (data[offset] |
            (data[offset + 1] << 8) |
            (data[offset + 2] << 16) |
            (data[offset + 3] << 24)) &
    0xFFFFFFFF;

/// Load 8 little-endian bytes as an unsigned 64-bit value.
int rawGet8(List<int> data, int offset) {
  final lo = rawGet4(data, offset);
  final hi = rawGet4(data, offset + 4);
  return ((hi << 32) | lo) & 0xFFFFFFFFFFFFFFFF;
}

/// Load 4 big-endian bytes as an unsigned 32-bit value.
int rawGetBe4(List<int> data, int offset) =>
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3];

/// Load 8 big-endian bytes as an unsigned 64-bit value.
int rawGetBe8(List<int> data, int offset) =>
    ((data[offset] << 56) |
            (data[offset + 1] << 48) |
            (data[offset + 2] << 40) |
            (data[offset + 3] << 32) |
            (data[offset + 4] << 24) |
            (data[offset + 5] << 16) |
            (data[offset + 6] << 8) |
            data[offset + 7]) &
    0xFFFFFFFFFFFFFFFF;

/// Store 2 little-endian bytes.
void rawPut2(int field, ByteWriter out) {
  out.writeByte(field & 0xff);
  out.writeByte((field >> 8) & 0xff);
}

/// Store 4 little-endian bytes.
void rawPut4(int field, ByteWriter out) {
  out.writeByte(field & 0xff);
  out.writeByte((field >> 8) & 0xff);
  out.writeByte((field >> 16) & 0xff);
  out.writeByte((field >> 24) & 0xff);
}

/// Store 8 little-endian bytes.
void rawPut8(int field, ByteWriter out) {
  for (var i = 0; i < 8; i++) {
    out.writeByte((field >> (8 * i)) & 0xff);
  }
}

/// Store 4 big-endian bytes.
void rawPutBe4(int field, ByteWriter out) {
  out.writeByte((field >> 24) & 0xff);
  out.writeByte((field >> 16) & 0xff);
  out.writeByte((field >> 8) & 0xff);
  out.writeByte(field & 0xff);
}

/// Store 8 big-endian bytes.
void rawPutBe8(int field, ByteWriter out) {
  for (var i = 7; i >= 0; i--) {
    out.writeByte((field >> (8 * i)) & 0xff);
  }
}

/// Checks whether [n] is a power of two, matching `IsPow2`.
bool isPow2(int n) => (n & (n - 1)) == 0;

/// Smallest power of two greater than or equal to [n], matching
/// `GetGreaterOrEqualPow2`.
int getGreaterOrEqualPow2(int n) {
  var p = 1;
  while (p < n) {
    p *= 2;
  }
  return p;
}

/// Largest power of two less than or equal to [n], matching
/// `GetLessOrEqualPow2`.
int getLessOrEqualPow2(int n) {
  var p = 1;
  while (p * 2 <= n) {
    p *= 2;
  }
  return p;
}

/// Minimal sink for the raw *put* helpers above.
abstract interface class ByteWriter {
  void writeByte(int value);
}
