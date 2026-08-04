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

  Future<RandomAccessFile> _open() async {
    _raf ??= await _file.open(mode: FileMode.read);
    return _raf!;
  }

  @override
  Future<Uint8List> read(int length) async {
    final raf = await _open();
    return raf.read(length);
  }

  @override
  Future<void> seek(int position) async {
    final raf = await _open();
    await raf.setPosition(position);
  }

  @override
  Future<int> position() async {
    final raf = await _open();
    return raf.position();
  }

  @override
  Future<int> length() async => _file.length();

  @override
  Future<void> close() async {
    await _raf?.close();
    _raf = null;
  }
}

/// Returns a [VolumeResolver] that looks for the next volume as a file on the
/// local file system. If [nextName] is a bare file name, it is resolved
/// relative to the directory that contains [currentName].
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
  final resolver =
      volumeResolver ?? (autoVolume ? fileVolumeResolver() : null);
  return RarArchive.open(
    FileByteSource(File(path)),
    password: password,
    archiveName: path,
    volumeResolver: resolver,
  );
}

