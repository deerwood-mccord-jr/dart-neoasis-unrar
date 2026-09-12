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
export 'src/archive_reader_sync.dart' show SyncArchiveReader;
export 'src/recvol.dart'
    show
        RevHeader,
        RevVolume,
        RevVolumeInfo,
        RecoveredVolumeWriter,
        readRevHeader,
        restoreVolumes;
export 'src/unpacker.dart';
export 'src/unrar_error.dart';
export 'src/volume.dart'
    show
        VolumeResolver,
        nextVolumeName,
        getVolumeNumber,
        firstVolumeName,
        volumeNumberStart;

import 'src/archive_entry.dart';
import 'src/archive_info.dart';
import 'src/archive_reader.dart';
import 'src/archive_reader_sync.dart';
import 'src/byte_source.dart';
import 'src/header_constants.dart';
import 'src/volume.dart';

/// An open RAR archive. Stored files and RAR 5.0/7.0, RAR 4.x, and RAR 1.5
/// compressed files can be extracted and CRC-verified.
class RarArchive {
  RarArchive._(this._reader);

  final ArchiveReader _reader;

  /// Opens [source] and detects the archive format and main header.
  ///
  /// Supply [password] for encrypted archives. If the archive has encrypted
  /// headers (`-hp` in `rar`) the password is used to derive the header
  /// decryption key; if only file data is encrypted it is used during
  /// extraction. An [UnrarException] is thrown if the password is wrong.
  ///
  /// For multi-part archives supply [archiveName] (the name/path of the first
  /// volume) and a [volumeResolver] that opens subsequent volumes on demand.
  /// When [volumeResolver] is `null`, split entries throw [UnrarException].
  /// `lib/io.dart`'s [openRarFile] automatically wires a file-system resolver.
  static Future<RarArchive> open(
    ByteSource source, {
    String? password,
    String? archiveName,
    VolumeResolver? volumeResolver,
  }) async {
    final reader = ArchiveReader(source,
        password: password,
        archiveName: archiveName,
        volumeResolver: volumeResolver);
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

/// Synchronous twin of [RarArchive] for in-memory archives only — no
/// `Future` anywhere in its surface, so it can be driven from ordinary
/// (non-`async`) code that genuinely cannot `await` (a synchronous
/// drag-and-drop virtual-file provider callback, for instance).
///
/// Backed by [SyncArchiveReader]/[MemorySyncByteSource]: reading already-
/// in-memory bytes has no real I/O to wait on, so this costs nothing over
/// the async [RarArchive] for that one case, and gains a call graph that
/// never needs an event-loop turn. See [SyncByteSource]'s doc comment for
/// why there is no disk-backed synchronous source, and
/// [SyncArchiveReader]'s for why multi-volume archives are out of scope
/// here (split entries throw instead of resolving further volumes).
class SyncRarArchive {
  SyncRarArchive._(this._reader);

  final SyncArchiveReader _reader;

  /// Opens [bytes] as a complete, self-contained RAR archive already held
  /// in memory and detects its format/main header. See [RarArchive.open]
  /// for the [password] contract this mirrors (multi-volume params aside —
  /// this class has none).
  factory SyncRarArchive.openBytes(Uint8List bytes, {String? password}) {
    final reader =
        SyncArchiveReader(MemorySyncByteSource(bytes), password: password);
    reader.init();
    return SyncRarArchive._(reader);
  }

  /// Detected archive format (RAR 4.x or RAR 5.0).
  RarFormat get format => _reader.format;

  /// `true` if any header checksum mismatch was detected while reading.
  bool get isBroken => _reader.isBroken;

  /// Lists all file entries in the archive.
  List<ArchiveEntry> list() => _reader.list();

  /// Extracts the first file entry named [name], returning its unpacked
  /// bytes, or `null` if no such file exists. Throws [UnrarException] if
  /// the entry spans multiple volumes (see [SyncArchiveReader]'s doc
  /// comment — this class only ever opens one, complete, in-memory
  /// archive).
  Uint8List? extractFile(String name) => _reader.extractFile(name);

  /// Releases the underlying source.
  void close() => _reader.close();
}
