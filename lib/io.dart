/// dart:io integration for neoasis_unrar.
///
/// Import this library (instead of `package:neoasis_unrar/neoasis_unrar.dart`)
/// when running on Dart VM / Flutter desktop and mobile. It stays out of the
/// core library so the core remains pure Dart.
library;

import 'dart:io';
import 'dart:typed_data';

import 'neoasis_unrar.dart';

/// A [ByteSource] backed by a file opened for random-access reading.
class FileByteSource implements ByteSource {
  FileByteSource(this._file);

  final File _file;
  RandomAccessFile? _raf;
  int _position = 0;
  int? _length;

  Future<RandomAccessFile> _open() async {
    _raf ??= await _file.open(mode: FileMode.read);
    return _raf!;
  }

  @override
  Future<Uint8List> read(int length) async {
    final raf = await _open();
    final bytes = await raf.read(length);
    _position += bytes.length;
    return bytes;
  }

  @override
  Future<void> seek(int position) async {
    final raf = await _open();
    await raf.setPosition(position);
    _position = position;
  }

  @override
  Future<int> position() async => _position;

  @override
  Future<int> length() async => _length ??= await _file.length();

  @override
  Future<void> close() async {
    await _raf?.close();
    _raf = null;
    _position = 0;
  }
}

/// Returns a [VolumeResolver] that looks for the next volume as a file on the
/// local file system. If `nextName` is a bare file name, it is resolved
/// relative to the directory that contains `currentName`.
VolumeResolver fileVolumeResolver() {
  return (String currentName, String nextName) async {
    // Resolve relative paths: if nextName has no directory component, place
    // it in the same directory as currentName.
    final File nextFile;
    if (nextName.contains('/') || nextName.contains('\\')) {
      nextFile = File(nextName);
    } else {
      final dir = File(currentName).parent;
      nextFile = File('${dir.path}/$nextName');
    }
    if (!nextFile.existsSync()) return null;
    return FileByteSource(nextFile);
  };
}

/// Opens the RAR archive at [path] for reading.
///
/// Supply [password] for encrypted archives (data or header encryption).
/// Multi-volume archives are automatically continued when the next part is
/// present alongside [path]; pass `autoVolume: false` to disable this, or
/// supply a custom [volumeResolver] to override the default file-system
/// resolver.
Future<RarArchive> openRarFile(
  String path, {
  String? password,
  bool autoVolume = true,
  VolumeResolver? volumeResolver,
}) {
  final resolver = volumeResolver ?? (autoVolume ? fileVolumeResolver() : null);
  return RarArchive.open(
    FileByteSource(File(path)),
    password: password,
    archiveName: path,
    volumeResolver: resolver,
  );
}

/// Rebuilds missing RAR 5.0 volumes using `*.rev` recovery volumes.
///
/// [archiveName] names any volume of the set (e.g. `arc.part1.rar` or
/// `arc.part1.rev`). The directory containing it is scanned for sibling
/// `*.partN.rar` and `*.partN.rev` files sharing the same name prefix; the
/// recovery volumes' headers identify the volume sizes and CRCs, and the
/// surviving volumes are checked against them.
///
/// Rebuilt volumes are written to [outputDir] (defaults to the directory
/// containing the volumes, overwriting corrupt volumes in place) under their
/// canonical `partN` names. Returns the paths of the rebuilt volumes.
///
/// Throws [UnrarException] when no valid recovery volume is found, the set is
/// inconsistent, or more volumes are missing than can be repaired.
Future<List<String>> restoreRevArchive(
  String archiveName, {
  String? outputDir,
  int chunkSize = 1 << 20,
}) async {
  final dirPath = File(archiveName).parent.path;
  final slash = archiveName.lastIndexOf('/');
  final backslash = archiveName.lastIndexOf('\\');
  final nameStart = (slash > backslash ? slash : backslash) + 1;
  final baseName = archiveName.substring(nameStart);

  final prefixEnd = volumeNumberStart(baseName);
  if (prefixEnd < 0) {
    throw const UnrarException('Volume name has no numeric part');
  }
  final prefix = baseName.substring(0, prefixEnd);
  final outDir = outputDir ?? dirPath;
  await Directory(outDir).create(recursive: true);

  final rarNames = <int, String>{};
  final revPaths = <String>[];
  await for (final entity in Directory(dirPath).list()) {
    if (entity is! File) continue;
    final name = entity.uri.pathSegments.last;
    if (!name.startsWith(prefix)) continue;
    if (name.toLowerCase().endsWith('.rar')) {
      final num = getVolumeNumber(name);
      if (num > 0) rarNames[num - 1] = entity.path;
    } else if (name.toLowerCase().endsWith('.rev')) {
      revPaths.add(entity.path);
    }
  }

  final revVolumes = <RevVolume>[];
  for (final path in revPaths) {
    final source = FileByteSource(File(path));
    try {
      final header = await readRevHeader(source);
      if (header == null) {
        await source.close();
        continue;
      }
      revVolumes.add(RevVolume(header: header, source: source));
    } catch (_) {
      await source.close();
    }
  }
  if (revVolumes.isEmpty) {
    throw const UnrarException('No valid recovery volumes found');
  }

  final nd = revVolumes[0].header.dataCount;
  final dataVolumes = List<ByteSource?>.filled(nd, null);
  for (final entry in rarNames.entries) {
    if (entry.key >= nd) continue;
    final source = FileByteSource(File(entry.value));
    try {
      await source.seek(0);
      dataVolumes[entry.key] = source;
    } catch (_) {
      await source.close();
    }
  }

  final base = firstVolumeName(baseName);
  final names = List<String>.generate(nd, (i) {
    var name = base;
    for (var k = 0; k < i; k++) {
      name = nextVolumeName(name);
    }
    return name;
  });

  final outFiles = <int, RandomAccessFile>{};
  try {
    final recovered = await restoreVolumes(
      dataVolumes: dataVolumes,
      revVolumes: revVolumes,
      chunkSize: chunkSize,
      writeChunk: (index, data, length) async {
        final raf = outFiles[index] ??=
            await File('$outDir/${names[index]}').open(mode: FileMode.write);
        await raf.writeFrom(data, 0, length);
      },
    );
    return [for (final index in recovered) '$outDir/${names[index]}'];
  } finally {
    for (final raf in outFiles.values) {
      await raf.close();
    }
    for (final source in dataVolumes) {
      await source?.close();
    }
    for (final rev in revVolumes) {
      await rev.source.close();
    }
  }
}
