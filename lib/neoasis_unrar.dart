/// A pure Dart implementation of the UnRAR library, ported from the RARLAB
/// C source code.
///
/// The core library has no `dart:io` dependency and works on any platform,
/// including the web. File-based access is provided by
/// `package:neoasis_unrar/io.dart`.
library;

import 'dart:async';
import 'dart:typed_data';

export 'src/archive_entry.dart';
export 'src/archive_info.dart';
export 'src/byte_source.dart';
export 'src/header_constants.dart';
export 'src/unpacker.dart';
export 'src/unrar_error.dart';

import 'src/archive_entry.dart';
import 'src/archive_info.dart';
import 'src/archive_reader.dart';
import 'src/byte_source.dart';
import 'src/header_constants.dart';

/// An open RAR archive. Stored files and RAR 5.0/7.0 compressed files can be
/// extracted and CRC-verified; RAR 4.x compressed entries are not supported
/// yet.
class RarArchive {
  RarArchive._(this._reader);

  final ArchiveReader _reader;

  /// Opens [source] and detects the archive format and main header.
  ///
  /// Supply [password] for encrypted archives. If the archive has encrypted
  /// headers (`-hp` in `rar`) the password is used to derive the header
  /// decryption key; if only file data is encrypted it is used during
  /// extraction. An [UnrarException] is thrown if the password is wrong.
  static Future<RarArchive> open(ByteSource source, {String? password}) async {
    final reader = ArchiveReader(source, password: password);
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

  /// Extracts every file entry in archive order, calling [onFile] with each
  /// entry and its fully unpacked, CRC-verified bytes.
  ///
  /// RAR 5.0/7.0 compressed entries and stored entries are supported; RAR 4.x
  /// compressed entries still throw [UnsupportedMethodException]. CRC
  /// mismatches raise [UnrarException].
  Future<void> extractAll(
          FutureOr<void> Function(ArchiveEntry entry, Uint8List data) onFile) =>
      _reader.extractAll(onFile);

  /// Extracts the first file entry named [name], returning its unpacked
  /// bytes, or `null` if no such file exists. See [extractAll] for the
  /// exceptions that can be raised.
  Future<Uint8List?> extractFile(String name) => _reader.extractFile(name);

  /// Verifies the archive structure and every entry's CRC32, returning
  /// `true` when all checks pass. Throws [UnsupportedMethodException] if any
  /// entry uses a compression method that cannot be verified yet.
  Future<bool> testArchive() => _reader.testArchive();

  /// Releases the underlying source.
  Future<void> close() => _reader.close();
}
