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

/// Opens the RAR archive at [path] for reading.
Future<RarArchive> openRarFile(String path) =>
    RarArchive.open(FileByteSource(File(path)));
