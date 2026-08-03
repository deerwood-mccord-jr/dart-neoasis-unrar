import 'dart:io';

import 'package:neoasis_unrar/io.dart';

/// Extracts a RAR archive into [outDir] (or the current directory).
///
/// Usage:
///   dart run example/bin/extract_archive.dart `archive.rar` `outDir`
///
/// RAR 5.0/7.0 compressed files and stored files are extracted; RAR 4.x
/// compressed entries still raise [UnsupportedMethodException].
Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln(
        'Usage: dart run example/bin/extract_archive.dart <archive.rar> [outDir]');
    exit(64);
  }

  final outDir = Directory(args.length > 1 ? args[1] : '.');
  await outDir.create(recursive: true);

  final archive = await openRarFile(args.first);
  var count = 0;
  await archive.extractAll((entry, data) async {
    final file = File('${outDir.path}${Platform.pathSeparator}${entry.name}');
    await file.parent.create(recursive: true);
    await file.writeAsBytes(data, flush: true);
    count++;
    stdout.writeln('extracted ${entry.name} (${data.length} bytes)');
  });

  stdout.writeln('Extracted $count file(s) to ${outDir.path}');
  await archive.close();
}
