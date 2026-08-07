import 'header_constants.dart';

/// Encryption parameters parsed from a file's `FHEXTRA_CRYPT` extra record
/// (RAR 5.0) or from the RAR 4.x per-file salt flag (`LHD_SALT`).
///
/// For RAR 5.0: mirrors `FileHeader::Salt`, `::InitV`, `::Lg2Count`,
/// `::PswCheck`, `::UseHashKey` from `headers.hpp`.
/// For RAR 4.x (`isRar4 == true`): only `salt` is populated (8 bytes);
/// the AES-128 key and IV are derived by the `kdf3` function from
/// `package:neoasis_unrar/src/kdf3.dart` using the password + salt.
class CryptInfo {
  const CryptInfo({
    required this.isRar4,
    required this.salt,
    this.iv,
    this.lg2Count = 0,
    this.pswCheck,
    this.usePswCheck = false,
    this.useHashKey = false,
  });

  /// `true` for RAR 4.x (AES-128, 8-byte salt); `false` for RAR 5.0
  /// (AES-256 / PBKDF2, 16-byte salt + 16-byte IV).
  final bool isRar4;

  /// Salt bytes (8 for RAR 4.x, 16 for RAR 5.0).
  final List<int> salt;

  /// AES-256 CBC initialisation vector (RAR 5.0 only, 16 bytes).
  final List<int>? iv;

  /// log₂ of PBKDF2 iteration count (RAR 5.0 only).
  final int lg2Count;

  /// 8-byte password-check value (present when [usePswCheck] is `true`).
  final List<int>? pswCheck;

  /// `true` if [pswCheck] is valid and should be tested before decrypting.
  final bool usePswCheck;

  /// `true` when the header's CRC32 field is a HMAC-SHA256 MAC rather than a
  /// plain CRC32 (RAR 5.0 `FHEXTRA_CRYPT_HASHMAC` flag).
  final bool useHashKey;
}

/// Hash algorithm used for a file's `FHEXTRA_HASH` record (RAR 5.0).
enum FileHashType {
  /// No hash record present.
  none,

  /// 32-byte BLAKE2sp digest of the unpacked file data.
  blake2;
}

/// Unix owner and group information from `FHEXTRA_UOWNER`, mirroring
/// `FileHeader::UnixOwnerSet` / `UnixOwnerName` / `UnixGroupName` from
/// `headers.hpp`.
class UnixOwnerInfo {
  const UnixOwnerInfo({
    this.ownerName,
    this.groupName,
    this.ownerId,
    this.groupId,
  });

  /// String owner name (UTF-8), or `null` if not stored.
  final String? ownerName;

  /// String group name (UTF-8), or `null` if not stored.
  final String? groupName;

  /// Numeric user ID, or `null` if not stored.
  final int? ownerId;

  /// Numeric group ID, or `null` if not stored.
  final int? groupId;
}

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
    this.cryptInfo,
    this.createdTime,
    this.accessedTime,
    this.redirectType = FileSystemRedirect.fsRedirNone,
    this.redirectTarget,
    this.redirectTargetIsDir = false,
    this.unixOwner,
    this.hashType = FileHashType.none,
    this.blake2Digest,
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

  /// File creation time from `FHEXTRA_HTIME`, or `null` if not stored.
  final DateTime? createdTime;

  /// Last-access time from `FHEXTRA_HTIME`, or `null` if not stored.
  final DateTime? accessedTime;

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

  /// Encryption parameters; `null` for unencrypted entries.
  final CryptInfo? cryptInfo;

  /// File system redirect type from `FHEXTRA_REDIR`; [FileSystemRedirect.fsRedirNone]
  /// when no redirection is present.
  final FileSystemRedirect redirectType;

  /// Target path for a file system redirect (symlink, junction, hard link …).
  /// `null` when [redirectType] is [FileSystemRedirect.fsRedirNone].
  final String? redirectTarget;

  /// `true` when the redirect target itself is a directory (the
  /// `FHEXTRA_REDIR_DIR` flag in RAR 5.0).
  final bool redirectTargetIsDir;

  /// `true` if this entry is any kind of file-system link (symlink, junction,
  /// hard link, or file copy).
  bool get isRedirect => redirectType != FileSystemRedirect.fsRedirNone;

  /// Unix owner/group information from `FHEXTRA_UOWNER`; `null` if absent.
  final UnixOwnerInfo? unixOwner;

  /// Hash algorithm stored in this entry's `FHEXTRA_HASH` record;
  /// [FileHashType.none] when the archive does not store a hash.
  final FileHashType hashType;

  /// Stored BLAKE2sp digest of the unpacked file data (32 bytes) when
  /// [hashType] is [FileHashType.blake2], otherwise `null`. For encrypted
  /// files this is the HMAC-SHA256-encrypted MAC of the digest
  /// (`hmacSha256(hashKey, digest)`).
  final List<int>? blake2Digest;

  @override
  String toString() =>
      '$name ($unpSize bytes, packed $packSize, dir=$isDirectory)';
}
