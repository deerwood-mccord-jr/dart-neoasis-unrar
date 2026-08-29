/// CRC32 implementation ported from the RARLAB UnRAR source (`crc.cpp`).
///
/// The reference implementation uses Intel Slicing-by-16 for performance.
/// This port uses slicing-by-8 for payload-sized ranges and the classic
/// byte-at-a-time algorithm for short headers.
library;

import 'dart:typed_data';

final List<Uint32List> _crc32Tables = _buildCrc32Tables();

List<Uint32List> _buildCrc32Tables() {
  final tables = List<Uint32List>.generate(8, (_) => Uint32List(256));
  final table = tables[0];
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) {
      c = (c & 1) != 0 ? ((c >> 1) ^ 0xEDB88320) : (c >> 1);
    }
    table[i] = c & 0xFFFFFFFF;
  }
  for (var slice = 1; slice < tables.length; slice++) {
    final previous = tables[slice - 1];
    final current = tables[slice];
    for (var i = 0; i < 256; i++) {
      final c = previous[i];
      current[i] = table[c & 0xff] ^ (c >>> 8);
    }
  }
  return tables;
}

/// Computes CRC32 over [data], matching
/// `uint CRC32(uint StartCRC, const void *Addr, size_t Size)`.
///
/// The caller supplies the running checksum in [startCrc] (usually
/// `0xffffffff`). When combining headers the convention is to XOR the
/// final result with `0xffffffff`.
int crc32(int startCrc, List<int> data, [int offset = 0, int? length]) {
  var crc = startCrc & 0xFFFFFFFF;
  final end = offset + (length ?? data.length - offset);
  final tables = _crc32Tables;
  final table = tables[0];
  var i = offset;
  if (end - i >= 64) {
    while (i + 8 <= end) {
      crc ^= (data[i] & 0xff) |
          ((data[i + 1] & 0xff) << 8) |
          ((data[i + 2] & 0xff) << 16) |
          ((data[i + 3] & 0xff) << 24);
      crc = tables[7][crc & 0xff] ^
          tables[6][(crc >>> 8) & 0xff] ^
          tables[5][(crc >>> 16) & 0xff] ^
          tables[4][(crc >>> 24) & 0xff] ^
          tables[3][data[i + 4] & 0xff] ^
          tables[2][data[i + 5] & 0xff] ^
          tables[1][data[i + 6] & 0xff] ^
          table[data[i + 7] & 0xff];
      i += 8;
    }
  }
  for (; i < end; i++) {
    crc = table[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return crc & 0xFFFFFFFF;
}

/// RAR 1.4 checksum used for very old archives, ported from
/// `ushort Checksum14(...)`.
int checksum14(int startCrc, List<int> data, [int offset = 0, int? length]) {
  var crc = startCrc & 0xffff;
  final end = offset + (length ?? data.length - offset);
  for (var i = offset; i < end; i++) {
    final byte = data[i];
    crc = (crc + byte) & 0xffff;
    crc = (((crc << 1) | (crc >> 15)) & 0xffff);
  }
  return crc;
}

/// Convenience wrapper for the common "CRC of a header" pattern.
int crc32Of(List<int> data) => crc32(0xffffffff, data) ^ 0xffffffff;
