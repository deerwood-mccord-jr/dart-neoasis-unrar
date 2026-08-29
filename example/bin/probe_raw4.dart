import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/src/crc.dart';
import 'package:neoasis_unrar/src/bit_input.dart';
import 'package:neoasis_unrar/src/unpack4.dart';
import 'package:neoasis_unrar/src/unpack_output.dart';

Future<void> main(List<String> args) async {
  for (final path in args) {
    final bytes = File(path).readAsBytesSync();
    stdout.writeln('== $path');
    final entries = _parse(bytes);
    final rar4 = Rar4Unpacker();
    for (final e in entries) {
      final out = rar4.unpack4(
        packed: PaddedInput.copyOf(
            Uint8List.sublistView(bytes, e.offset, e.offset + e.packSize)),
        output: UnpackOutput(expectedSize: e.unpSize, collect: true),
        unpSize: e.unpSize,
        windowSize: e.windowSize,
        solid: false,
        unpVer: e.unpVer,
      );
      final data = out.bytes ?? Uint8List(0);
      stdout.writeln(
          '  ${e.name}: out=${data.length} crc=${crc32Of(data).toRadixString(16)}'
          ' want=${e.crc32.toRadixString(16)}'
          ' all=${data.toList()}');
    }
  }
}

class _Entry {
  final String name;
  final int packSize;
  final int unpSize;
  final int unpVer;
  final int windowSize;
  final int crc32;
  final int offset;
  _Entry(this.name, this.packSize, this.unpSize, this.unpVer, this.windowSize,
      this.crc32, this.offset);
}

List<_Entry> _parse(Uint8List b) {
  final out = <_Entry>[];
  var pos = 0;
  while (pos + 7 <= b.length) {
    final crc = _u16(b, pos);
    final type = b[pos + 2];
    final flags = _u16(b, pos + 3);
    final headSize = _u16(b, pos + 5);
    stdout.writeln('  hdr @$pos type=${type.toRadixString(16)} '
        'flags=${flags.toRadixString(16)} size=$headSize');
    if (crc == 0 && headSize == 0) break;
    if (type == 0x74) {
      final packSize = _u32(b, pos + 7);
      final unpSize = _u32(b, pos + 11);
      final fileCrc = _u32(b, pos + 16);
      final unpVer = b[pos + 24];
      final dataOffset = pos + headSize;
      final isDir = (flags & 0x0400) != 0;
      final win = isDir ? 0 : 0x10000 << ((flags >> 5) & 0x7);
      out.add(_Entry('', packSize, unpSize, unpVer, win, fileCrc, dataOffset));
      pos += headSize + packSize;
      continue;
    }
    pos += headSize;
  }
  return out;
}

int _u16(Uint8List b, int p) => b[p] | (b[p + 1] << 8);
int _u32(Uint8List b, int p) =>
    b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);
