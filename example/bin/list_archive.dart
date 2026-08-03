import 'dart:io';

import 'package:neoasis_unrar/io.dart';

/// Lists the contents of a RAR archive.
///
/// Usage:
///   dart run example/bin/list_archive.dart `archive.rar`
Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('Usage: dart run example/bin/list_archive.dart <archive.rar>');
    exit(64);
  }

  final archive = await openRarFile(args.first);

  final info = archive.info;
  print('Format:    ${archive.format}');
  print('Solid:     ${info.solid}');
  print('Locked:    ${info.locked}');
  print('Encrypted: ${info.encrypted}');
  print('');

  final entries = await archive.list();
  for (final entry in entries) {
    final type = entry.isDirectory ? 'd' : 'f';
    final packed = _formatSize(entry.packSize);
    final unpacked = _formatSize(entry.unpSize);
    final time = entry.modifiedTime?.toIso8601String() ?? '';
    print('$type  $packed  $unpacked  $time  ${entry.name}');
  }

  await archive.close();
}

String _formatSize(int bytes) => bytes.toString().padLeft(12);
