/// CRC32 implementation ported from the RARLAB UnRAR source (`crc.cpp`).
///
/// The reference implementation uses Intel Slicing-by-16 for performance.
/// This port uses the classic single-table byte-at-a-time algorithm, which
/// produces identical results. A slicing variant can be added later if
/// profiling shows it is needed.
library;

final List<int> _crc32Table = _buildCrc32Table();

List<int> _buildCrc32Table() {
  final table = List<int>.filled(256, 0);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) {
      c = (c & 1) != 0 ? ((c >> 1) ^ 0xEDB88320) : (c >> 1);
    }
    table[i] = c & 0xFFFFFFFF;
  }
  return table;
}

/// Computes CRC32 over [data], matching
/// `uint CRC32(uint StartCRC, const void *Addr, size_t Size)`.
///
/// The caller supplies the running checksum in [startCrc] (usually
/// `0xffffffff`). When combining headers the convention is to XOR the
/// final result with `0xffffffff`.
int crc32(int startCrc, List<int> data, [int offset = 0, int? length]) {
  var crc = startCrc;
  final end = offset + (length ?? data.length - offset);
  final table = _crc32Table;
  for (var i = offset; i < end; i++) {
    crc = (table[(crc ^ data[i]) & 0xff] ^ (crc >> 8)) & 0xFFFFFFFF;
  }
  return crc;
}

/// RAR 1.4 checksum used for very old archives, ported from
/// `ushort Checksum14(...)`.
int checksum14(int startCrc, List<int> data) {
  var crc = startCrc & 0xffff;
  for (final byte in data) {
    crc = (crc + byte) & 0xffff;
    crc = (((crc << 1) | (crc >> 15)) & 0xffff);
  }
  return crc;
}

/// Convenience wrapper for the common "CRC of a header" pattern.
int crc32Of(List<int> data) => crc32(0xffffffff, data) ^ 0xffffffff;
