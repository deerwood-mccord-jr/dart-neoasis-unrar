import 'dart:typed_data';

import 'package:neoasis_unrar/src/byte_source.dart';
import 'package:neoasis_unrar/src/raw_reader.dart';
import 'package:test/test.dart';

class _TestSource implements ByteSource {
  _TestSource(this._bytes);

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
  Future<void> seek(int position) async => _pos = position;

  @override
  Future<int> position() async => _pos;

  @override
  Future<int> length() async => _bytes.length;

  @override
  Future<void> close() async {}
}

void main() {
  group('RawReader', () {
    test('Get1/Get2/Get4/Get8 are little-endian', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
      ])));
      await raw.read(16);
      expect(raw.get1(), 0x01);
      expect(raw.get2(), 0x0302); // [0x02, 0x03] little-endian
      expect(raw.get4(), 0x07060504); // [0x04..0x07] little-endian
      expect(raw.get8(), 0x0F0E0D0C0B0A0908); // [0x08..0x0F] little-endian
    });

    test('GetV decodes variable-length integers', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([
        0x01, // 1
        0x80, 0x01, // 1 << 7 = 128
        0xff, 0x7f, // 127 + 127<<7 = 16383
      ])));
      await raw.read(5);
      expect(raw.getV(), 1);
      expect(raw.getV(), 128);
      expect(raw.getV(), 0x7f + (0x7f << 7));
    });

    test('GetVSize returns the encoded length', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([
        0x81, 0x82, 0x03, 0x04,
      ])));
      await raw.read(4);
      expect(raw.getVSize(0), 3);
      expect(raw.getVSize(1), 2);
    });

    test('GetB zero-fills shortages', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([1, 2, 3])));
      await raw.read(3);
      expect(raw.getB(5), [1, 2, 3, 0, 0]);
      expect(raw.dataLeft, 0);
    });

    test('GetCRC15 matches a hand-built RAR4 header', () async {
      // Build a 7 byte header and store the correct CRC in bytes [0..1].
      final crc = _makeHeader15Crc(_makeHeader15(crc: 0));
      final data = _makeHeader15(crc: crc);
      final raw = RawReader(_TestSource(data));
      await raw.read(7);
      expect(raw.get2(), crc); // head CRC
      raw.get1(); // type
      raw.get2(); // flags
      raw.get2(); // size
      expect(raw.getCRC15(), crc);
    });

    test('GetCRC50 matches a hand-built RAR5 header', () async {
      final crc = _makeHeader50Crc(_makeHeader50(crc: 0));
      final data = _makeHeader50(crc: crc);
      final raw = RawReader(_TestSource(data));
      await raw.read(data.length);
      expect(raw.get4(), crc); // CRC
      raw.getV(); // size
      expect(raw.getCRC50(), crc);
    });

    test('Compact preserves unread data', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([1, 2, 3, 4])));
      await raw.read(4);
      raw.get2();
      raw.compact();
      expect(raw.get2(), 3 + (4 << 8)); // little-endian [3, 4]
    });

    test('out-of-bounds reads return zero', () async {
      final raw = RawReader(_TestSource(Uint8List.fromList([1])));
      await raw.read(1);
      expect(raw.get2(), 0);
      expect(raw.get4(), 0);
    });
  });
}

Uint8List _makeHeader15({required int crc}) {
  final b = Uint8List(7);
  b[0] = crc & 0xff;
  b[1] = (crc >> 8) & 0xff;
  b[2] = 0x74; // HEAD3_FILE
  b[3] = 0x00; // flags lo
  b[4] = 0x00; // flags hi
  b[5] = 0x07; // size lo
  b[6] = 0x00; // size hi
  return b;
}

int _makeHeader15Crc(Uint8List data) {
  // CRC32 over Data[2..end] starting from 0xffffffff, then inverted.
  return (crc32Internal(data) ^ 0xffffffff) & 0xffff;
}

int crc32Internal(Uint8List data) {
  final table = _table();
  var crc = 0xffffffff;
  for (var i = 2; i < data.length; i++) {
    crc = (table[(crc ^ data[i]) & 0xff] ^ (crc >> 8)) & 0xffffffff;
  }
  return crc;
}

Uint8List _makeHeader50({required int crc}) {
  final body = Uint8List.fromList([
    0x01, // type: HEAD_MAIN
    0x00, // flags
  ]);
  final total = Uint8List(4 + 1 + body.length); // crc(4) + size(vint) + body
  total[0] = crc & 0xff;
  total[1] = (crc >> 8) & 0xff;
  total[2] = (crc >> 16) & 0xff;
  total[3] = (crc >> 24) & 0xff;
  total[4] = body.length; // size vint (single byte)
  for (var i = 0; i < body.length; i++) {
    total[5 + i] = body[i];
  }
  return total;
}

int _makeHeader50Crc(Uint8List data) {
  // CRC32 over Data[4..end] starting from 0xffffffff, XORed with 0xffffffff.
  final table = _table();
  var crc = 0xffffffff;
  for (var i = 4; i < data.length; i++) {
    crc = (table[(crc ^ data[i]) & 0xff] ^ (crc >> 8)) & 0xffffffff;
  }
  return crc ^ 0xffffffff;
}

List<int> _table() {
  final table = List<int>.filled(256, 0);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var j = 0; j < 8; j++) {
      c = (c & 1) != 0 ? ((c >> 1) ^ 0xEDB88320) : (c >> 1);
    }
    table[i] = c & 0xffffffff;
  }
  return table;
}
