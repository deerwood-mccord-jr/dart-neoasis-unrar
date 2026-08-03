/// A pure Dart implementation of the UnRAR library, ported from the RARLAB
/// C source code.
///
/// The core library has no `dart:io` dependency and works on any platform,
/// including the web. File-based access is provided by
/// `package:neoasis_unrar/io.dart`.
library;

export 'src/archive_entry.dart';
export 'src/archive_info.dart';
export 'src/byte_source.dart';
export 'src/header_constants.dart';
export 'src/unrar_error.dart';

import 'src/archive_entry.dart';
import 'src/archive_info.dart';
import 'src/archive_reader.dart';
import 'src/byte_source.dart';
import 'src/header_constants.dart';

/// An open RAR archive. Read-only at this milestone; extraction is a future
/// milestone.
class RarArchive {
  RarArchive._(this._reader);

  final ArchiveReader _reader;

  /// Opens [source] and detects the archive format and main header.
  static Future<RarArchive> open(ByteSource source) async {
    final reader = ArchiveReader(source);
    await reader.init();
    return RarArchive._(reader);
  }

  /// Detected archive format (RAR 4.x or RAR 5.0).
  RarFormat get format => _reader.format;

  /// Properties parsed from the main archive header.
  ArchiveInfo get info => _reader.info;

  /// Offset of the RAR signature within the source (0 for plain archives,
  /// greater than 0 for SFX stubs).
  int get sfxSize => _reader.sfxSize;

  /// `true` if any header checksum mismatch was detected while reading.
  bool get isBroken => _reader.isBroken;

  /// Lists all file entries in the archive.
  Future<List<ArchiveEntry>> list() => _reader.list();

  /// Releases the underlying source.
  Future<void> close() => _reader.close();
}
