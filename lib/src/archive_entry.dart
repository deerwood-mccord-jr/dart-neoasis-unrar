import 'header_constants.dart';

/// A single entry (file or directory) inside a RAR archive, modeled on the
/// `FileHeader` struct from the RARLAB UnRAR source (`headers.hpp`).
class ArchiveEntry {
  const ArchiveEntry({
    required this.name,
    required this.packSize,
    required this.unpSize,
    required this.isDirectory,
    required this.isEncrypted,
    required this.isSolid,
    required this.splitBefore,
    required this.splitAfter,
    required this.crc32,
    required this.modifiedTime,
    required this.method,
    required this.unpVer,
    required this.hostOs,
    required this.fileAttr,
    required this.flags,
    required this.windowSize,
    required this.unknownUnpSize,
    required this.isService,
    required this.hostSystemType,
  });

  /// Full path of the entry inside the archive.
  final String name;

  /// Compressed (packed) size in bytes.
  final int packSize;

  /// Uncompressed (unpacked) size in bytes. May be [int64Ndf] if unknown.
  final int unpSize;

  /// `true` if this entry is a directory.
  final bool isDirectory;

  /// `true` if the file data is encrypted.
  final bool isEncrypted;

  /// `true` if the file belongs to a solid stream and requires all preceding
  /// files to be decompressed first.
  final bool isSolid;

  final bool splitBefore;

  final bool splitAfter;

  /// CRC32 of the unpacked data (0 if the archive does not store one).
  final int crc32;

  /// Modification time, or `null` if not stored.
  final DateTime? modifiedTime;

  /// Compression method (0 - 5).
  final int method;

  /// Unpack format version (e.g. 29, 50, 70).
  final int unpVer;

  /// Host OS that created the file (see [hostUnix], [hostWin32], ...).
  final int hostOs;

  /// OS-specific file attributes.
  final int fileAttr;

  /// Raw header flags.
  final int flags;

  /// LZ dictionary window size in bytes (0 for directories).
  final int windowSize;

  final bool unknownUnpSize;

  /// `true` for HEAD_SERVICE blocks (non-file records like comments or
  /// recovery records).
  final bool isService;

  final HostSystemType hostSystemType;

  @override
  String toString() =>
      '$name ($unpSize bytes, packed $packSize, dir=$isDirectory)';
}
