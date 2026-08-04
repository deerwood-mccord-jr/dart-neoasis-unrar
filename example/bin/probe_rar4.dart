import 'dart:io';

import 'package:neoasis_unrar/io.dart';

Future<void> main(List<String> args) async {
  for (final path in args) {
    final archive = await openRarFile(path);
    final info = archive.info;
    stdout.writeln('== $path');
    stdout.writeln(
        '  volume=${info.volume} solid=${info.solid}');
    for (final entry in await archive.list()) {
      stdout.writeln('  - ${entry.name}');
      stdout.writeln('      method=${entry.method} unpVer=${entry.unpVer} '
          'windowSize=${entry.windowSize} pack=${entry.packSize} '
          'unp=${entry.unpSize} solid=${entry.isSolid} '
          'crc=${entry.crc32.toRadixString(16)}');
    }
    await archive.close();
  }
}
