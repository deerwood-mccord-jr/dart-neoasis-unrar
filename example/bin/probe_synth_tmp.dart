import 'dart:typed_data';

import 'package:neoasis_unrar/src/archive_reader.dart';
import 'package:neoasis_unrar/src/byte_source.dart';

Future<void> main() async {
  final bytes = _rar4Archive();
  final reader = ArchiveReader(MemoryByteSource(bytes));
  await reader.init();
  final entries = await reader.list();
  final e = entries.single;
  print('method=${e.method} unpVer=${e.unpVer} pack=${e.packSize} unp=${e.unpSize}');
  try {
    final out = await reader.extractFile(e.name);
    print('OK bytes=${out!.length} first=${out.take(16).toList()}');
  } catch (err) {
    print('ERR: $err');
  }
}

Uint8List _rar4Archive() {
  final out = <int>[];
  out.addAll('Rar!\x1a\x07\x00'.codeUnits);
  out.addAll(_header15([
    0x73, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ]));
  final name = 'hello.txt'.codeUnits;
  final headSize = 32 + name.length;
  out.addAll(_header15([
    0x74, 0x00, 0x00, headSize & 0xff, (headSize >> 8) & 0xff, 0x0a, 0x00,
    0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02, 0x78, 0x56, 0x34, 0x12,
    ..._dosTime(2020, 1, 2, 3, 4, 6), 0x1d, 0x32, name.length & 0xff,
    (name.length >> 8) & 0xff, 0x20, 0x00, 0x00, 0x00, ...name,
  ]));
  out.addAll(List.filled(10, 0x00));
  out.addAll(_header15([0x7b, 0x00, 0x00, 0x07, 0x00]));
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

List<int> _dosTime(int y, int m, int d, int h, int mi, int s) {
  final v = (s ~/ 2) |
      (mi << 5) |
      (h << 11) |
      (d << 16) |
      (m << 21) |
      ((y - 1980) << 25);
  return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
}

List<int> _table() {
  final t = List<int>.filled(256, 0);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? 0xedb88320 ^ (c >> 1) : c >> 1;
    }
    t[i] = c;
  }
  return t;
}
