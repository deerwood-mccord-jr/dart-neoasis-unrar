import 'dart:typed_data';

import 'package:neoasis_unrar/src/archive_reader.dart';
import 'package:neoasis_unrar/src/byte_source.dart';
import 'package:neoasis_unrar/src/header_constants.dart';
import 'package:neoasis_unrar/src/unrar_error.dart';
import 'package:test/test.dart';

void main() {
  group('RAR 4.x archive', () {
    test('lists file entries', () async {
      final bytes = _rar4Archive();
      final reader = ArchiveReader(MemoryByteSource(bytes));
      await reader.init();

      expect(reader.format, RarFormat.rarFmt15);
      expect(reader.info.solid, isFalse);
      expect(reader.info.locked, isFalse);

      final entries = await reader.list();
      expect(entries, hasLength(1));
      final e = entries.first;
      expect(e.name, 'hello.txt');
      expect(e.packSize, 10);
      expect(e.unpSize, 100);
      expect(e.crc32, 0x12345678);
      expect(e.method, 2);
      expect(e.unpVer, 29);
      expect(e.isDirectory, isFalse);
      expect(e.isEncrypted, isFalse);
      expect(e.hostSystemType, HostSystemType.hsysWindows);
      expect(e.modifiedTime, DateTime(2020, 1, 2, 3, 4, 6));
    });

    test('detects solid flag from main header', () async {
      final bytes = _rar4Archive(solid: true);
      final reader = ArchiveReader(MemoryByteSource(bytes));
      await reader.init();
      expect(reader.info.solid, isTrue);
    });

    test('skips an SFX stub', () async {
      final stub = <int>[
        for (var i = 0; i < 16; i++) 0x90, // junk / executable bytes
        ..._rar4Archive(),
      ];
      final reader = ArchiveReader(MemoryByteSource(Uint8List.fromList(stub)));
      await reader.init();
      expect(reader.sfxSize, 16);
      expect((await reader.list()).single.name, 'hello.txt');
    });
  });

  group('RAR 5.0 archive', () {
    test('lists file entries', () async {
      final bytes = _rar5Archive();
      final reader = ArchiveReader(MemoryByteSource(bytes));
      await reader.init();

      expect(reader.format, RarFormat.rarFmt50);
      expect(reader.info.newNumbering, isTrue);

      final entries = await reader.list();
      expect(entries, hasLength(1));
      final e = entries.first;
      expect(e.name, 'hello.txt');
      expect(e.packSize, 10);
      expect(e.unpSize, 100);
      expect(e.crc32, 0x12345678);
      expect(e.method, 2);
      expect(e.unpVer, verPack5);
      expect(e.isDirectory, isFalse);
      expect(e.hostSystemType, HostSystemType.hsysWindows);
    });

    test('detects volume flags from main header', () async {
      final bytes = _rar5Archive(volume: true, volNumber: 2);
      final reader = ArchiveReader(MemoryByteSource(bytes));
      await reader.init();
      expect(reader.info.volume, isTrue);
      expect(reader.info.volNumber, 2);
      expect(reader.info.firstVolume, isFalse);
    });
  });

  group('errors', () {
    test('rejects non-RAR data', () async {
      final reader = ArchiveReader(
          MemoryByteSource(Uint8List.fromList(List.filled(64, 0x41))));
      await expectLater(reader.init(), throwsA(isA<UnrarFormatException>()));
    });

    test('rejects data that is too short', () async {
      final reader =
          ArchiveReader(MemoryByteSource(Uint8List.fromList([0x52, 0x61])));
      await expectLater(reader.init(), throwsA(isA<UnrarFormatException>()));
    });

    test('rejects a corrupt main header CRC', () async {
      final bytes = _rar4Archive();
      bytes[8] ^= 0xff; // Corrupt the main header CRC.
      final reader = ArchiveReader(MemoryByteSource(bytes));
      await expectLater(reader.init(), throwsA(isA<UnrarHeaderException>()));
    });
  });
}

// ---------------------------------------------------------------------------
// RAR 4.x archive builder.
// ---------------------------------------------------------------------------

Uint8List _rar4Archive({bool solid = false}) {
  final out = <int>[];

  // Mark.
  out.addAll('Rar!\x1a\x07\x00'.codeUnits);

  // Main header (13 bytes total).
  out.addAll(_header15([
    0x73, // HEAD3_MAIN
    solid ? 0x08 : 0x00, 0x00, // flags (MHD_SOLID)
    0x0d, 0x00, // head size 13
    0x00, 0x00, // high pos av
    0x00, 0x00, 0x00, 0x00, // pos av
  ]));

  // File header.
  final name = 'hello.txt'.codeUnits;
  final headSize = 32 + name.length;
  out.addAll(_header15([
    0x74, // HEAD3_FILE
    0x00, 0x00, // flags
    headSize & 0xff, (headSize >> 8) & 0xff, // head size
    0x0a, 0x00, 0x00, 0x00, // pack size 10
    0x64, 0x00, 0x00, 0x00, // unp size 100
    0x02, // host OS: win32
    0x78, 0x56, 0x34, 0x12, // file CRC
    ..._dosTime(2020, 1, 2, 3, 4, 6), // file time
    0x1d, // unp ver 29
    0x32, // method 2
    name.length & 0xff, (name.length >> 8) & 0xff, // name size
    0x20, 0x00, 0x00, 0x00, // attr
    ...name,
  ]));

  // Packed data area (10 bytes).
  out.addAll(List.filled(10, 0x00));

  // End of archive header (7 bytes).
  out.addAll(_header15([
    0x7b, // HEAD3_ENDARC
    0x00, 0x00, // flags
    0x07, 0x00, // head size 7
  ]));

  return Uint8List.fromList(out);
}

List<int> _header15(List<int> body) {
  final full = List<int>.filled(body.length + 2, 0);
  for (var i = 0; i < body.length; i++) {
    full[i + 2] = body[i];
  }
  final crc = _crc15(full);
  full[0] = crc & 0xff;
  full[1] = (crc >> 8) & 0xff;
  return full;
}

int _crc15(List<int> full) {
  var crc = 0xffffffff;
  final table = _table();
  for (var i = 2; i < full.length; i++) {
    crc = (table[(crc ^ full[i]) & 0xff] ^ (crc >> 8)) & 0xffffffff;
  }
  return (~crc) & 0xffff;
}

List<int> _dosTime(int year, int month, int day, int hour, int minute,
    int second) {
  final v = (second ~/ 2) |
      (minute << 5) |
      (hour << 11) |
      (day << 16) |
      (month << 21) |
      ((year - 1980) << 25);
  return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
}

// ---------------------------------------------------------------------------
// RAR 5.0 archive builder.
// ---------------------------------------------------------------------------

Uint8List _rar5Archive({bool volume = false, int volNumber = 0}) {
  final out = <int>[];

  // Mark (8 bytes).
  out.addAll('Rar!\x1a\x07\x01\x00'.codeUnits);

  // Main header.
  final mainArcFlags = (volume ? 0x01 : 0) | (volNumber > 0 ? 0x02 : 0);
  final mainBody = <int>[
    0x01, // HEAD_MAIN
    0x00, // flags
    ..._vint(mainArcFlags),
    if (volNumber > 0) ..._vint(volNumber),
  ];
  out.addAll(_header50(mainBody));

  // File header.
  final name = 'hello.txt'.codeUnits;
  final fileBody = <int>[
    0x02, // HEAD_FILE
    hflData, // flags: data area present
    ..._vint(10), // data size (packed size)
    fhflCrc32, // file flags
    ..._vint(100), // unp size
    ..._vint(0x20), // file attr
    0x78, 0x56, 0x34, 0x12, // CRC32
    ..._vint(2 << 7), // comp info: method 2, algorithm 0
    ..._vint(host5Windows), // host OS
    ..._vint(name.length), // name size
    ...name,
  ];
  out.addAll(_header50(fileBody));

  // Packed data area (10 bytes).
  out.addAll(List.filled(10, 0x00));

  // End of archive header.
  out.addAll(_header50([
    0x05, // HEAD_ENDARC
    0x00, // flags
    ..._vint(0), // arc flags
  ]));

  return Uint8List.fromList(out);
}

List<int> _header50(List<int> body) {
  final full = <int>[
    ..._vint(body.length), // block size
    ...body,
  ];
  final crc = _crc50(full);
  return [
    crc & 0xff,
    (crc >> 8) & 0xff,
    (crc >> 16) & 0xff,
    (crc >> 24) & 0xff,
    ...full,
  ];
}

int _crc50(List<int> block) {
  var crc = 0xffffffff;
  final table = _table();
  for (var i = 0; i < block.length; i++) {
    crc = (table[(crc ^ block[i]) & 0xff] ^ (crc >> 8)) & 0xffffffff;
  }
  return crc ^ 0xffffffff;
}

List<int> _vint(int value) {
  final bytes = <int>[];
  while (value >= 0x80) {
    bytes.add((value & 0x7f) | 0x80);
    value >>= 7;
  }
  bytes.add(value);
  return bytes;
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
