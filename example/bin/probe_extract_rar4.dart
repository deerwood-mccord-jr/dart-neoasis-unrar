import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/src/archive_reader.dart';
import 'package:neoasis_unrar/src/byte_source.dart';
import 'package:neoasis_unrar/src/crc.dart';

Future<void> main(List<String> args) async {
  for (final path in args) {
    final bytes = File(path).readAsBytesSync();
    final reader = ArchiveReader(ByteSourceFromBytes(bytes));
    await reader.init();
    stdout.writeln('== $path');
    for (final entry in await reader.list()) {
      stdout.writeln(
          '  - ${entry.name} method=${entry.method} unpVer=${entry.unpVer} '
          'windowSize=${entry.windowSize} pack=${entry.packSize} '
          'unp=${entry.unpSize} crc=${entry.crc32.toRadixString(16)}');
      try {
        final out = await reader.extractFile(entry.name);
        final actual = crc32Of(out!);
        stdout.writeln(
            '      extract: ${out.length} bytes crc=${actual.toRadixString(16)} '
            'match=${actual == entry.crc32}');
        if (actual != entry.crc32) {
          stdout.writeln('      first32=${out.take(32).toList()}');
        }
      } catch (err) {
        stdout.writeln('      extract ERR: $err');
      }
    }
  }
}

class ByteSourceFromBytes implements ByteSource {
  ByteSourceFromBytes(this._bytes);
  final Uint8List _bytes;
  int _pos = 0;
  @override
  Future<void> seek(int pos) async {
    _pos = pos;
  }

  @override
  Future<Uint8List> read(int count) async {
    final end = (_pos + count).clamp(0, _bytes.length);
    final out = _bytes.sublist(_pos, end);
    _pos = end;
    return out;
  }

  @override
  Future<int> length() async => _bytes.length;

  @override
  Future<int> position() async => _pos;

  @override
  Future<void> close() async {}
}
