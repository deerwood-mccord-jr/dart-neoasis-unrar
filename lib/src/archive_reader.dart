import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'aes.dart';
import 'archive_entry.dart';
import 'archive_info.dart';
import 'blake2s.dart';
import 'byte_source.dart';
import 'crc.dart';
import 'enc_name.dart';
import 'header_constants.dart';
import 'kdf3.dart';
import 'kdf5.dart';
import 'rar_time.dart';
import 'raw_reader.dart';
import 'sha256.dart';
import 'unpacker.dart';
import 'unrar_error.dart';
import 'volume.dart';

/// A single parsed block header, mirroring the fields used by the C code's
/// `BaseBlock`/`BlockHeader` structs.
class _BlockHeader {
  int headCrc = 0;
  HeaderType type = HeaderType.headUnknown;
  int flags = 0;
  int headSize = 0;

  /// Size of the data area following the header (packed size for files).
  int dataSize = 0;

  /// Absolute position of the data area following the header.
  int dataOffset = 0;

  bool skipIfUnknown = false;

  /// Parsed entry for HEAD_FILE blocks.
  ArchiveEntry? entry;

  // RAR 4.x end-of-archive fields (HEAD_ENDARC).

  /// `true` when EARC_NEXT_VOLUME is absent — this is the last volume.
  bool isLastVolume = false;

  /// `true` when EARC_REVSPACE is set — the last 7 bytes may be zeroed by
  /// a REV file.  Used to suppress false CRC errors on recovered volumes.
  bool hasRevSpace = false;
}

/// Reads archive blocks sequentially from a [ByteSource], ported from the
/// RARLAB UnRAR `Archive` class (`arcread.cpp`, `archive.cpp`).
///
/// Supports RAR 4.x (RAR 1.5 format, `ReadHeader15`) and RAR 5.0
/// (`ReadHeader50`) block layouts. Parsing is limited to the main and file
/// headers; encrypted headers require a password via [password].
///
/// Multi-volume extraction requires a [volumeResolver] callback. When a file
/// entry spans multiple volumes the reader calls the resolver with the
/// current archive name and the computed next-volume name to obtain the next
/// [ByteSource]. The [archiveName] is used only to derive the next-volume
/// filename; it does not affect reading.
class ArchiveReader {
  ArchiveReader(
    this._source, {
    String? password,
    String? archiveName,
    VolumeResolver? volumeResolver,
  })  : _password = password,
        _archiveName = archiveName,
        _volumeResolver = volumeResolver,
        _unpacker = Unpacker(_source);

  final ByteSource _source;

  /// Optional decryption password supplied by the caller.
  final String? _password;

  /// The archive's filename/path, used to compute next-volume names.
  final String? _archiveName;

  /// Callback that opens the next volume in a multi-part set, or `null` if
  /// multi-volume extraction is not supported by this reader instance.
  final VolumeResolver? _volumeResolver;

  /// Shared decompressor, reused across entries so the RAR 5.0/7.0 window
  /// state carries through solid streams.
  final Unpacker _unpacker;

  RarFormat _format = RarFormat.rarFmtNone;
  final ArchiveInfo _info = ArchiveInfo();
  bool _encrypted = false;
  bool _brokenHeader = false;
  int _sfxSize = 0;
  bool _initialized = false;

  // CurBlockPos / NextBlockPos in the C code.
  int _blockPos = 0;

  int _nextBlockPos = 0;

  /// Absolute position of the first block after the main header, used to
  /// rewind before extraction.
  int _firstBlockPos = 0;

  // --- RAR 5.0 archive-level encryption head (HEAD_CRYPT block) ---

  /// 16-byte salt from HEAD_CRYPT (RAR 5.0 -hp).
  List<int>? _rar5CryptSalt;

  /// lg2Count from HEAD_CRYPT (RAR 5.0 -hp).
  int _rar5CryptLg2 = 0;

  /// Stored 8-byte pswCheck from HEAD_CRYPT (RAR 5.0 -hp).
  List<int>? _rar5PswCheck;

  /// Whether [_rar5PswCheck] is valid (digest verified).
  bool _rar5UsePswCheck = false;

  /// Derived AES-256 decryptor for RAR 5.0 encrypted headers.
  AesCbcDecryptor? _rar5HeaderDecryptor;

  // --- RAR 3 archive-level encryption salt (main-header -hp) ---
  // (Stored for potential diagnostics; the derived key is in _rar3HeaderDecryptor.)

  RarFormat get format => _format;

  ArchiveInfo get info => _info;

  bool get isBroken => _brokenHeader;

  int get sfxSize => _sfxSize;

  bool get isEncrypted => _encrypted;

  /// Detects the format, reads the archive mark, and positions the source at
  /// the first block after the main header.
  Future<void> init() async {
    if (_initialized) {
      return;
    }
    await _init();
    _initialized = true;
  }

  Future<void> _init() async {
    final first = await _readExact(7);
    if (first.length < 7) {
      throw const UnrarFormatException('Not a RAR archive');
    }

    var format = _isSignature(first, 0, 7);
    var sfxPos = 0;

    if (format == RarFormat.rarFmtNone) {
      // Scan for a signature inside an SFX stub. `rest` starts at file
      // offset 7, so the mark's absolute position is 7 + sfxPos.
      final rest = await _source.read(maxSfxSize);
      final found = _findSignature(rest);
      if (found < 0) {
        throw const UnrarFormatException('Not a RAR archive');
      }
      format = _isSignature(rest, found, rest.length - found);
      sfxPos = found + 7;
      await _source.seek(sfxPos);
      await _readExact(7); // Consume the mark again, like the C code.
    }

    if (format == RarFormat.rarFmtFuture) {
      throw const UnrarFormatException(
          'Archive uses an unknown future RAR format');
    }
    if (format == RarFormat.rarFmt14) {
      _format = format;
      _sfxSize = sfxPos;
      // RAR 1.4 signature is only 4 bytes; we read 7 above, so seek back
      // 3 bytes so that the main-header reader starts at the right position.
      await _source.seek(sfxPos + 4);
      final mainFound2 = await _readHeader14Main();
      if (!mainFound2) {
        throw const UnrarFormatException('RAR 1.4 main header is missing');
      }
      _firstBlockPos = _nextBlockPos;
      return;
    }
    if (format == RarFormat.rarFmtNone) {
      throw const UnrarFormatException('Not a RAR archive');
    }

    _format = format;
    _sfxSize = sfxPos;

    if (_format == RarFormat.rarFmt50) {
      // RAR 5.0 signature is one byte longer; the 8th byte must be zero.
      final extra = await _readExact(1);
      if (extra.length != 1 || extra[0] != 0) {
        throw const UnrarFormatException('Corrupt RAR 5.0 signature');
      }
    }

    // Read headers until the main header is found, skipping anything before
    // it (e.g. an encryption header in RAR 5.0).
    var mainFound = false;
    while (true) {
      final head = await _readHeader();
      if (head == null) {
        break;
      }
      await _seekToNext();
      if (head.type == HeaderType.headMain) {
        mainFound = true;
        break;
      }
    }

    if (_encrypted) {
      if (_password == null) {
        throw const UnrarException(
            'Archive headers are encrypted: supply a password');
      }
      // For RAR 5.0 the HEAD_CRYPT block was already parsed and the derived
      // decryptor is set; for RAR 4.x the decryptor is set when the 8-byte
      // salt preamble is read in _readHeader15.
    }

    if (!mainFound) {
      throw const UnrarFormatException('Main archive header is missing');
    }

    if (_brokenHeader) {
      throw const UnrarHeaderException('Main archive header is corrupt');
    }

    _firstBlockPos = _nextBlockPos;
    await _seekToNext();
  }

  /// Repositions the reader to the first block after the main header.
  Future<void> _rewind() async {
    _blockPos = _firstBlockPos;
    await _source.seek(_firstBlockPos);
  }

  /// Returns the list of file entries (skipping service blocks), positioned
  /// after the main header.
  Future<List<ArchiveEntry>> list() async {
    if (!_initialized) {
      await init();
    }
    final entries = <ArchiveEntry>[];
    while (true) {
      final head = await _readHeader();
      if (head == null) {
        break;
      }
      if (head.type == HeaderType.headEndArc) {
        break;
      }
      if (head.type == HeaderType.headFile && head.entry != null) {
        entries.add(head.entry!);
      }
      await _seekToNext();
    }
    return entries;
  }

  Future<void> close() async {
    _unpacker.clearSensitiveState();
    _rar3HeaderDecryptor = null;
    _rar5HeaderDecryptor = null;
    await _source.close();
  }

  /// Extracts every file entry in archive order, invoking [onFile] with each
  /// entry and its fully unpacked, CRC-verified bytes. Directories and
  /// service blocks are skipped. Throws [UnsupportedMethodException] for
  /// unsupported compression methods and [UnrarException] on CRC mismatches.
  Future<void> extractAll(
      FutureOr<void> Function(ArchiveEntry entry, Uint8List data)
          onFile) async {
    if (!_initialized) {
      await init();
    } else {
      await _rewind();
    }
    while (true) {
      final head = await _readHeader();
      if (head == null || head.type == HeaderType.headEndArc) {
        break;
      }
      final entry = head.entry;
      if (entry != null && !entry.isDirectory) {
        final data = await _unpackEntry(entry, head);
        await onFile(entry, data);
      }
      await _seekToNext();
    }
  }

  /// Extracts the first file entry named [name], or `null` if not present.
  ///
  /// Header positions let us seek straight to the data of non-solid entries,
  /// so they are extracted without touching preceding files. Compressed
  /// entries of a solid stream depend on the files before them, so those are
  /// unpacked first to keep the decompressor's window state consistent.
  Future<Uint8List?> extractFile(String name) async {
    if (!_initialized) {
      await init();
    } else {
      await _rewind();
    }
    while (true) {
      final head = await _readHeader();
      if (head == null || head.type == HeaderType.headEndArc) {
        return null;
      }
      final entry = head.entry;
      if (entry != null && !entry.isDirectory) {
        if (entry.name == name) {
          return _unpackEntry(entry, head);
        }
        // In a solid archive every compressed file shares one LZ window with
        // the files before it (the first file of the stream has no solid
        // flag), so unpack-and-discard them to keep the decompressor state
        // consistent for the requested entry.
        if (_info.solid && entry.method != 0) {
          await _unpackEntry(entry, head);
        }
      }
      await _seekToNext();
    }
  }

  /// Verifies the archive structure and every entry's CRC32, returning
  /// `true` when all checks pass. Throws [UnsupportedMethodException] if any
  /// entry uses a compression method that cannot be verified yet.
  Future<bool> testArchive() async {
    if (!_initialized) {
      await init();
    } else {
      await _rewind();
    }
    while (true) {
      final head = await _readHeader();
      if (head == null || head.type == HeaderType.headEndArc) {
        break;
      }
      final entry = head.entry;
      if (entry != null && !entry.isDirectory) {
        await _unpackEntry(entry, head, collectOutput: false);
      }
      await _seekToNext();
    }
    return !_brokenHeader;
  }

  Future<Uint8List> _unpackEntry(ArchiveEntry entry, _BlockHeader head,
      {bool collectOutput = true}) async {
    // FSREDIR_FILECOPY and FSREDIR_HARDLINK: resolve the source entry.
    // Both reference a file already in the archive and have no data area of
    // their own. Mirrors `ExtractFileCopy` / `ExtractHardlink` in extract.cpp.
    if (entry.redirectType == FileSystemRedirect.fsRedirFileCopy ||
        entry.redirectType == FileSystemRedirect.fsRedirHardLink) {
      final sourceName = entry.redirectTarget;
      if (sourceName == null || sourceName.isEmpty) {
        throw UnrarException(
            'Redirect entry "${entry.name}" has no redirect target');
      }
      final source = await extractFile(sourceName);
      if (source == null) {
        throw UnrarException(
            'Redirect entry "${entry.name}" points to missing source '
            '"$sourceName" (ERAR_EREFERENCE)');
      }
      return source;
    }

    if (entry.isEncrypted) {
      if (_password == null) {
        throw const UnrarException(
            'File is encrypted: supply a password to extract it');
      }
      if (entry.cryptInfo == null) {
        throw const UnrarException(
            'File is marked encrypted but has no crypto parameters');
      }
    }
    if (entry.splitBefore) {
      // The caller should never arrive at a split-before entry without having
      // already assembled the preceding parts.  If it happens, it means the
      // user opened a middle or last volume directly.
      throw const UnrarException(
          'Entry starts in a preceding volume; open the first part');
    }
    if (entry.splitAfter) {
      return _unpackSplit(entry, head, collectOutput: collectOutput);
    }
    // For RAR 1.4 entries the crc32 field holds a 16-bit Checksum14 value.
    // Pass expectedCrc=0 to suppress the CRC32 check inside the unpacker,
    // then verify manually using checksum14 (mirroring HASH_RAR14 in hash.cpp).
    final isRar14 = entry.unpVer == 10 || entry.unpVer == 13;
    final crcForUnpacker = isRar14 ? 0 : entry.crc32;

    final out = await _unpacker.unpack(
      method: entry.method,
      packSize: head.dataSize,
      unpSize: entry.unpSize,
      unknownUnpSize: entry.unknownUnpSize,
      dataOffset: head.dataOffset,
      expectedCrc: crcForUnpacker,
      unpVer: entry.unpVer,
      windowSize: entry.windowSize,
      solid: entry.isSolid,
      password: _password,
      cryptInfo: entry.cryptInfo,
      hashType: entry.hashType,
      blake2Digest: entry.blake2Digest,
      // RAR 1.4 checksum verification below still requires the bytes. Other
      // formats verify incrementally in the unpack output sink.
      collectOutput: collectOutput || isRar14,
    );

    if (isRar14 && entry.crc32 != 0) {
      final actual = checksum14(0, out);
      if (actual != entry.crc32) {
        throw UnrarException(
            'Checksum14 mismatch for RAR 1.4 entry "${entry.name}" '
            '(expected 0x${entry.crc32.toRadixString(16)}, '
            'got 0x${actual.toRadixString(16)})');
      }
    }
    return out;
  }

  /// Assembles packed data for an entry that spans multiple volumes, then
  /// decompresses/verifies the concatenated stream. Mirrors the `MergeArchive`
  /// / `UnpPackedLeft` continuation logic in `volume.cpp`.
  Future<Uint8List> _unpackSplit(
      ArchiveEntry firstEntry, _BlockHeader firstHead,
      {bool collectOutput = true}) async {
    final resolver = _volumeResolver;
    final arcName = _archiveName;
    if (resolver == null || arcName == null) {
      throw const UnrarException(
          'File spans multiple volumes: provide a VolumeResolver via '
          'RarArchive.open to extract split entries');
    }

    // Collect packed data fragments from successive volumes.
    final fragments = <Uint8List>[];

    // Fragment from this (first) volume.
    await _source.seek(firstHead.dataOffset);
    fragments.add(await _readUpTo(firstHead.dataSize));

    // Walk subsequent volumes until splitAfter is false.
    var currentArcName = arcName;
    var currentEntry = firstEntry;
    var rar4Old = _format == RarFormat.rarFmt15 && !_info.newNumbering;

    while (currentEntry.splitAfter) {
      final nextName = nextVolumeName(currentArcName, oldNumbering: rar4Old);
      final nextSource = await resolver(currentArcName, nextName);
      if (nextSource == null) {
        throw UnrarException('Cannot locate next volume: $nextName');
      }

      // Open a temporary reader for the next volume, passing through the
      // password and volume resolver so chains of 3+ volumes are followed.
      final nextReader = ArchiveReader(
        nextSource,
        password: _password,
        archiveName: nextName,
        volumeResolver: _volumeResolver,
      );
      await nextReader.init();

      // Mirror volume.cpp:148-156: abort if encrypted-header state changes
      // across the volume boundary (prevents volume-injection attacks).
      if (nextReader.isEncrypted != _encrypted) {
        await nextSource.close();
        throw const UnrarException(
            'Volume encryption state changed between volumes — '
            'possible volume injection attack');
      }

      // Find the continuation entry (splitBefore=true) in the next volume.
      _BlockHeader? contHead;
      ArchiveEntry? contEntry;
      await nextReader._rewind();
      while (true) {
        final h = await nextReader._readHeader();
        if (h == null || h.type == HeaderType.headEndArc) break;
        if (h.type == HeaderType.headFile && h.entry != null) {
          final e = h.entry!;
          if (e.splitBefore && e.name == firstEntry.name) {
            contHead = h;
            contEntry = e;
            break;
          }
        }
        await nextReader._seekToNext();
      }

      if (contHead == null || contEntry == null) {
        await nextSource.close();
        throw UnrarException(
            'Volume $nextName does not contain a continuation of '
            '${firstEntry.name}');
      }

      await nextSource.seek(contHead.dataOffset);
      fragments.add(await nextReader._readUpTo(contHead.dataSize));

      currentEntry = contEntry;
      currentArcName = nextName;
      await nextSource.close();
    }

    // The CRC in the LAST part's header is the whole-file CRC (for all parts
    // except the last it is the packed-data CRC of that part only).
    final fullFileCrc = currentEntry.crc32;

    // Concatenate all fragments into a single packed stream.
    final totalSize = fragments.fold<int>(0, (s, f) => s + f.length);
    final packed = Uint8List(totalSize);
    var offset = 0;
    for (final f in fragments) {
      packed.setRange(offset, offset + f.length, f);
      offset += f.length;
    }

    // Decrypt if needed (only RAR 5.0 per-file or RAR 4.x AES; use the
    // first entry's crypto parameters since they apply to the whole file).
    final cryptInfo = firstEntry.cryptInfo;
    final pwd = _password;
    final decrypted = (cryptInfo != null && pwd != null)
        ? _unpacker.decryptPacked(packed, pwd, cryptInfo, firstEntry.crc32)
        : packed;

    // Decompress or copy the assembled plaintext.
    return _unpacker.unpackFromBuffer(
      method: firstEntry.method,
      unpSize: firstEntry.unpSize,
      unknownUnpSize: firstEntry.unknownUnpSize,
      expectedCrc: fullFileCrc,
      unpVer: firstEntry.unpVer,
      windowSize: firstEntry.windowSize,
      solid: firstEntry.isSolid,
      data: decrypted,
      password: pwd,
      cryptInfo: cryptInfo,
      alreadyDecrypted: true,
      hashType: firstEntry.hashType,
      blake2Digest: firstEntry.blake2Digest,
      collectOutput: collectOutput,
    );
  }

  Future<Uint8List> _readUpTo(int size) async {
    final buf = Uint8List(size);
    var written = 0;
    while (written < size) {
      final chunk = await _source.read(size - written);
      if (chunk.isEmpty) break;
      buf.setRange(written, written + chunk.length, chunk);
      written += chunk.length;
    }
    return written == size ? buf : Uint8List.sublistView(buf, 0, written);
  }

  Future<void> _seekToNext() => _source.seek(_nextBlockPos);

  Future<Uint8List> _readExact(int size) async {
    final buffer = Uint8List(size);
    var written = 0;
    while (written < size) {
      final chunk = await _source.read(size - written);
      if (chunk.isEmpty) {
        break;
      }
      final copyLength =
          chunk.length > size - written ? size - written : chunk.length;
      buffer.setRange(written, written + copyLength, chunk);
      written += copyLength;
    }
    return written == size ? buffer : Uint8List.sublistView(buffer, 0, written);
  }

  Future<_BlockHeader?> _readHeader() async {
    _blockPos = await _source.position();
    switch (_format) {
      case RarFormat.rarFmt14:
        return _readHeader14();
      case RarFormat.rarFmt15:
        return _readHeader15();
      case RarFormat.rarFmt50:
        return _readHeader50();
      default:
        return null;
    }
  }

  // --- RAR 3 archive-level encryption decryptor for -hp headers ---
  AesCbcDecryptor? _rar3HeaderDecryptor;

  // ---------------------------------------------------------------------
  // RAR 4.x (RAR 1.5 format) block reading.

  // ---------------------------------------------------------------------
  // RAR 1.4 (rarFmt14) block reading.
  // Ported from `Archive::ReadHeader14` in `arcread.cpp`.
  // ---------------------------------------------------------------------

  /// Reads the RAR 1.4 main header (first block after the 4-byte signature).
  Future<bool> _readHeader14Main() async {
    // The main header is 7 bytes: 4-byte mark already consumed as signature,
    // so RAR 1.4 main = headSize(2) + flags(1) — read 3 more bytes.
    // Per C code: Raw.Read(SIZEOF_MAINHEAD14) = 7 bytes, but 4-byte mark first.
    // CurBlockPos is the signature start; we already consumed 4 bytes.
    final raw = await _readExact(3);
    if (raw.length < 3) return false;
    // raw[0..1] = headSize LE, raw[2] = flags
    final headSize = raw[0] | (raw[1] << 8);
    if (headSize < 7) return false;
    final flags = raw[2];
    _info.volume = (flags & mhdVolume) != 0;
    _info.solid = (flags & mhdSolid) != 0;
    _info.locked = (flags & mhdLock) != 0;
    _info.encrypted = (flags & mhdPassword) != 0;
    _info.newNumbering = false; // RAR 1.4 uses old numbering.
    // Skip any remaining bytes of the main header.
    final toSkip = headSize - 7;
    if (toSkip > 0) {
      await _readExact(toSkip);
    }
    _nextBlockPos = _sfxSize + headSize;
    await _source.seek(_nextBlockPos);
    return true;
  }

  /// Reads the next RAR 1.4 file header from the current source position.
  Future<_BlockHeader?> _readHeader14() async {
    // RAR 1.4 file header: 21 bytes minimum.
    // dataSize(4) + unpSize(4) + crc(2) + headSize(2) + fileTime(4)
    // + fileAttr(1) + flags(1) + unpVer(1) + nameSize(1) + method(1)
    const minSize = 21;
    final raw = await _readExact(minSize);
    if (raw.length < minSize) return null;

    final dataSize = raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24);
    final unpSize = raw[4] | (raw[5] << 8) | (raw[6] << 16) | (raw[7] << 24);
    // raw[8..9] = RAR 1.4 16-bit checksum (`HASH_RAR14`).
    // Store it directly in crc32; it will be verified after extraction
    // using checksum14() rather than crc32Of().
    final checksum = raw[8] | (raw[9] << 8);
    final headSize = raw[10] | (raw[11] << 8);
    if (headSize < minSize) return null;
    final fileTime =
        raw[12] | (raw[13] << 8) | (raw[14] << 16) | (raw[15] << 24);
    final fileAttr = raw[16];
    final flags14 = raw[17];
    final unpVerByte = raw[18];
    final nameSize = raw[19];
    final method = raw[20] - 0x30;
    // Read the file name.
    final nameBytes = await _readExact(nameSize);
    final name = String.fromCharCodes(nameBytes);

    // Skip remaining header bytes.
    final headerBodyRead = minSize + nameSize;
    if (headSize > headerBodyRead) {
      await _readExact(headSize - headerBodyRead);
    }

    _nextBlockPos = _blockPos + headSize + dataSize;
    final head = _BlockHeader()
      ..type = HeaderType.headFile
      ..headSize = headSize
      ..dataSize = dataSize
      ..dataOffset = _blockPos + headSize
      ..flags = flags14 | longBlock; // Mark as long block like RAR 4.x.

    // RAR 1.4 uses unpVer 13 (byte == 2) or 10 (older).
    final unpVer = (unpVerByte == 2) ? 13 : 10;
    final isDir = (fileAttr & 0x10) != 0;

    head.entry = ArchiveEntry(
      name: name,
      packSize: dataSize,
      unpSize: unpSize,
      isDirectory: isDir,
      isEncrypted: (flags14 & lhdPassword) != 0,
      isSolid: false,
      splitBefore: (flags14 & lhdSplitBefore) != 0,
      splitAfter: (flags14 & lhdSplitAfter) != 0,
      // RAR 1.4 stores a 16-bit Checksum14 value (rotate-add, not CRC32).
      // Store it in the crc32 field; _unpack15 will verify using checksum14().
      crc32: checksum,
      modifiedTime: dosTimeToDateTime(fileTime),
      method: method,
      unpVer: unpVer,
      hostOs: hostMsDos,
      fileAttr: fileAttr,
      flags: flags14 | longBlock,
      windowSize: 0x10000,
      unknownUnpSize: unpSize == 0xffffffff,
      isService: false,
      hostSystemType: HostSystemType.hsysWindows,
    );
    return head;
  }
  // ---------------------------------------------------------------------

  Future<_BlockHeader?> _readHeader15() async {
    // If the archive uses header encryption (-hp), the content after the
    // mark starts with an 8-byte salt followed by AES-128-CBC encrypted
    // header blocks. Mirror `Archive::ReadHeader15` from arcread.cpp.
    final needsDecrypt = _encrypted && _blockPos > _sfxSize + sizofMarkHead3;

    if (needsDecrypt && _rar3HeaderDecryptor == null) {
      // First time: read the 8-byte salt and derive the key.
      if (_password == null) {
        throw const UnrarException(
            'Archive headers are encrypted: supply a password');
      }
      final salt = await _readExact(sizeSalt30);
      if (salt.length != sizeSalt30) {
        return null;
      }
      final kdf = kdf3(_password, salt);
      _rar3HeaderDecryptor =
          AesCbcDecryptor(Aes.withKey(Uint8List.fromList(kdf.key)), kdf.init);
    }

    final raw = RawReader(_source,
        decryptor: needsDecrypt ? _rar3HeaderDecryptor : null);
    if (await raw.read(sizofShortBlockHead) == 0) {
      return null;
    }

    final head = _BlockHeader();
    head.headCrc = raw.get2();
    final rawType = raw.get1();
    head.flags = raw.get2();
    head.skipIfUnknown = (head.flags & skipIfUnknown) != 0;
    head.headSize = raw.get2();

    head.type = _mapHeaderType15(rawType);
    if (head.headSize < sizofShortBlockHead) {
      _brokenHeader = true;
      return null;
    }

    // Mirror arcread.cpp:203-221: a comment block (HEAD3_CMT) and a main
    // header with an embedded pre-RAR 3.0 comment (MHD_COMMENT) only CRC the
    // fixed header fields, not the (possibly compressed) comment body, so
    // read only those fields here and let _nextBlockPos skip the rest.
    //
    // Read no more than the block actually contains: well-formed in-header
    // comments (headSize >= SIZEOF_MAINHEAD3) read the fixed 6 bytes of the
    // main fields; degenerate blocks that are smaller (e.g. RAR 2.x archives
    // that flag MHD_COMMENT but store the comment as a separate HEAD3_CMT
    // block) have their CRC computed over the base fields alone.
    if (head.type == HeaderType.head3Cmt) {
      final fixed = sizofCommHead - sizofShortBlockHead;
      final extra = head.headSize - sizofShortBlockHead;
      await raw.read(fixed < extra ? fixed : extra);
    } else if (head.type == HeaderType.headMain &&
        (head.flags & mhdComment) != 0) {
      final fixed = sizofMainHead3 - sizofShortBlockHead;
      final extra = head.headSize - sizofShortBlockHead;
      await raw.read(fixed < extra ? fixed : extra);
    } else {
      await raw.read(head.headSize - sizofShortBlockHead);
    }

    _nextBlockPos = _blockPos + head.headSize;
    head.dataOffset = _nextBlockPos;

    switch (head.type) {
      case HeaderType.headMain:
        _info.reset();
        _info.highPosAv = raw.get2();
        _info.posAv = raw.get4();
        _info.volume = (head.flags & mhdVolume) != 0;
        _info.solid = (head.flags & mhdSolid) != 0;
        _info.locked = (head.flags & mhdLock) != 0;
        _info.protected = (head.flags & mhdProtect) != 0;
        _info.encrypted = (head.flags & mhdPassword) != 0;
        _info.firstVolume = (head.flags & mhdFirstVolume) != 0;
        _info.newNumbering = (head.flags & mhdNewNumbering) != 0;
        _info.comment = (head.flags & mhdComment) != 0;
        _info.signed = _info.posAv != 0 || _info.highPosAv != 0;
        _encrypted = _info.encrypted;
        break;
      case HeaderType.headFile:
      case HeaderType.headService:
        head.entry = _parseFileHeader15(
          raw,
          head,
          isService: head.type == HeaderType.headService,
        );
        _nextBlockPos = (_nextBlockPos + head.dataSize) & 0xFFFFFFFFFFFFFFFF;
        // RAR 3.x/4.x Unix symlinks: the target path is stored as the file's
        // data (always method=0, no encryption).  Read it eagerly so that
        // callers see a populated redirectTarget after list().  Mirrors
        // `ExtractUnixLink30` in `ulinks.cpp`.
        final e = head.entry;
        if (e != null &&
            e.redirectType == FileSystemRedirect.fsRedirUnixSymlink &&
            e.redirectTarget == null &&
            e.method == 0 &&
            head.dataSize > 0 &&
            head.dataSize <= maxPathSize &&
            !e.isEncrypted) {
          final savedPos = _nextBlockPos;
          await _source.seek(head.dataOffset);
          final targetBytes = await _readExact(head.dataSize);
          final end = targetBytes.indexOf(0);
          final slice = end == -1 ? targetBytes : targetBytes.sublist(0, end);
          // Target path is stored as bytes in the host locale; UTF-8 on Unix.
          final target = utf8.decode(slice, allowMalformed: true);
          head.entry = ArchiveEntry(
            name: e.name,
            packSize: e.packSize,
            unpSize: e.unpSize,
            isDirectory: e.isDirectory,
            isEncrypted: e.isEncrypted,
            isSolid: e.isSolid,
            splitBefore: e.splitBefore,
            splitAfter: e.splitAfter,
            crc32: e.crc32,
            modifiedTime: e.modifiedTime,
            createdTime: e.createdTime,
            accessedTime: e.accessedTime,
            method: e.method,
            unpVer: e.unpVer,
            hostOs: e.hostOs,
            fileAttr: e.fileAttr,
            flags: e.flags,
            windowSize: e.windowSize,
            unknownUnpSize: e.unknownUnpSize,
            isService: e.isService,
            hostSystemType: e.hostSystemType,
            cryptInfo: e.cryptInfo,
            redirectType: e.redirectType,
            redirectTarget: target,
            redirectTargetIsDir: e.redirectTargetIsDir,
            unixOwner: e.unixOwner,
            hashType: e.hashType,
            blake2Digest: e.blake2Digest,
          );
          // Restore _nextBlockPos (seek does not move _nextBlockPos).
          _nextBlockPos = savedPos;
        }
        break;
      case HeaderType.headEndArc:
        // Parse EARC flags so we can detect the RevSpace guard below.
        // EARC_NEXT_VOLUME / EARC_DATACRC / EARC_REVSPACE / EARC_VOLNUMBER.
        final earcNextVol = (head.flags & earcNextVolume) != 0;
        final earcDataCrc = (head.flags & 0x0002) != 0;
        if (earcDataCrc) raw.skip(4); // 4-byte archive CRC (ignored).
        final earcRevSp = (head.flags & earcRevSpace) != 0;
        if ((head.flags & earcVolNumber) != 0) {
          raw.skip(2); // 2-byte volume number.
        }
        head.isLastVolume = !earcNextVol;
        head.hasRevSpace = earcRevSp;
        break;
      case HeaderType.head3Protect:
        head.dataSize = raw.get4();
        _nextBlockPos = (_nextBlockPos + head.dataSize) & 0xFFFFFFFFFFFFFFFF;
        break;
      case HeaderType.head3Cmt:
        // Old standalone comment header (HEAD3_CMT, 0x75).  Reads the 6-byte
        // comment sub-header fields; sets the comment flag.  The comment text
        // is compressed and lives after headSize — skip it (headSize already
        // accounts for the full header, no separate data area).
        raw.skip(2); // UnpSize
        raw.skip(1); // UnpVer
        raw.skip(1); // Method
        raw.skip(2); // CommCRC
        _info.comment = true;
        break;
      case HeaderType.head3Av:
      case HeaderType.head3Sign:
        // AV (0x76) and signature (0x79) headers: no data area; CRC is not
        // reliable on these blocks (intentional in the C source). Nothing to
        // parse — just let _nextBlockPos stay at headSize.
        break;
      case HeaderType.head3OldService:
        // RAR 2.x subblock (HEAD3_OLDSERVICE, 0x77).  DataSize(4) precedes
        // the sub-type fields and the data area follows the header.
        final dataSize3 = raw.get4();
        _nextBlockPos = (_nextBlockPos + dataSize3) & 0xFFFFFFFFFFFFFFFF;
        break;
      default:
        if ((head.flags & longBlock) != 0) {
          _nextBlockPos = (_nextBlockPos + raw.get4()) & 0xFFFFFFFFFFFFFFFF;
        }
    }

    // File/service headers with an embedded comment (LHD_COMMENT) only CRC
    // the parsed fields, excluding the comment body (arcread.cpp:430).
    final commentInHeader = (head.type == HeaderType.headFile ||
            head.type == HeaderType.headService) &&
        (head.flags & lhdComment) != 0;
    final headerCrc = raw.getCRC15(processedOnly: commentInHeader);
    if (head.headCrc != headerCrc) {
      // AV and signature blocks have unreliable CRCs (intentional in the C
      // source — arcread.cpp:520-521); do not mark the archive as broken.
      final crcNotReliable =
          head.type == HeaderType.head3Av || head.type == HeaderType.head3Sign;

      // Mirror arcread.cpp:524-547: if the end-of-archive header has
      // EARC_REVSPACE set, the last 7 bytes of the file may have been
      // overwritten with zeroes by a REV recovery tool.  If they are all
      // zero, treat the header as intact rather than marking it broken.
      bool recovered = false;
      if (head.hasRevSpace) {
        final len = await _source.length();
        if (len >= 7) {
          await _source.seek(len - 7);
          final tail = await _source.read(7);
          recovered = tail.length == 7 && tail.every((b) => b == 0);
        }
      }
      if (!crcNotReliable && !recovered) {
        _brokenHeader = true;
      }
    }
    return head;
  }

  ArchiveEntry? _parseFileHeader15(
    RawReader raw,
    _BlockHeader head, {
    required bool isService,
  }) {
    final dataSize = raw.get4();
    final lowUnpSize = raw.get4();
    final hostOs = raw.get1();
    final fileCrc = raw.get4();
    final fileTime = raw.get4();
    final unpVer = raw.get1();
    final method = raw.get1() - 0x30;
    final nameSize = raw.get2();
    final fileAttr = raw.get4();

    final largeFile = (head.flags & lhdLarge) != 0;
    var highPackSize = 0;
    var highUnpSize = 0;
    var unknownUnpSize = false;
    if (largeFile) {
      highPackSize = raw.get4();
      highUnpSize = raw.get4();
      unknownUnpSize = lowUnpSize == 0xffffffff && highUnpSize == 0xffffffff;
    } else {
      unknownUnpSize = lowUnpSize == 0xffffffff;
    }
    final packSize = ((highPackSize << 32) | dataSize) & 0xFFFFFFFFFFFFFFFF;
    var unpSize = ((highUnpSize << 32) | lowUnpSize) & 0xFFFFFFFFFFFFFFFF;
    if (unknownUnpSize) {
      unpSize = int64Ndf;
    }
    head.dataSize = packSize;

    final readNameSize = nameSize < maxPathSize ? nameSize : maxPathSize;
    final rawName = raw.getB(readNameSize);
    final name = _decodeName15(rawName, head.flags);

    if (isService) {
      // A "CMT" sub-header marks the archive as having a comment
      // (matching `MainComment` in `arcread.cpp`).
      if (name.toUpperCase() == 'CMT') {
        _info.comment = true;
      }
      // Skip any remaining extra data and return null.
      if ((head.flags & lhdSalt) != 0) {
        raw.skip(sizeSalt30);
      }
      return null;
    }

    CryptInfo? cryptInfo;
    if ((head.flags & lhdSalt) != 0) {
      final salt = raw.getB(sizeSalt30);
      cryptInfo = CryptInfo(isRar4: true, salt: salt);
    }

    var modifiedTime = dosTimeToDateTime(fileTime);
    DateTime? createdTime15;
    DateTime? accessedTime15;
    if ((head.flags & lhdExtTime) != 0) {
      final ext = _parseExtTime(raw, fileTime, modifiedTime);
      modifiedTime = ext.mtime;
      createdTime15 = ext.ctime;
      accessedTime15 = ext.atime;
    }

    final isDir = (head.flags & lhdWindowMask) == lhdDirectory;
    final windowSize =
        isDir ? 0 : 0x10000 << ((head.flags & lhdWindowMask) >> 5);

    // RAR 4.x Unix symlink: host is Unix and fileAttr high nibble = 0xA
    // (S_IFLNK), matching `ConvertFileHeader` in the C code.
    final isUnixHost = hostOs == hostUnix || hostOs == hostBeos;
    final isUnixSymlink =
        isUnixHost && (fileAttr & 0xf000) == 0xa000 /* S_IFLNK */;
    final redirectType = isUnixSymlink
        ? FileSystemRedirect.fsRedirUnixSymlink
        : FileSystemRedirect.fsRedirNone;

    return ArchiveEntry(
      name: name,
      packSize: packSize,
      unpSize: unpSize,
      isDirectory: isDir,
      isEncrypted: (head.flags & lhdPassword) != 0,
      isSolid: (head.flags & lhdSolid) != 0,
      splitBefore: (head.flags & lhdSplitBefore) != 0,
      splitAfter: (head.flags & lhdSplitAfter) != 0,
      crc32: fileCrc,
      modifiedTime: modifiedTime,
      createdTime: createdTime15,
      accessedTime: accessedTime15,
      method: method,
      unpVer: unpVer,
      hostOs: hostOs,
      fileAttr: fileAttr,
      flags: head.flags,
      windowSize: windowSize,
      unknownUnpSize: unknownUnpSize,
      isService: false,
      hostSystemType: isUnixHost
          ? HostSystemType.hsysUnix
          : hostOs < hostMax
              ? HostSystemType.hsysWindows
              : HostSystemType.hsysUnknown,
      cryptInfo: cryptInfo,
      redirectType: redirectType,
    );
  }

  String _decodeName15(List<int> rawName, int flags) {
    if ((flags & lhdUnicode) != 0) {
      var length = 0;
      while (length < rawName.length && rawName[length] != 0) {
        length++;
      }
      length++; // Include the null terminator.
      if (length < rawName.length) {
        return decodeEncodedName(rawName, rawName.sublist(length));
      }
    }
    final end = rawName.indexOf(0);
    final slice = end == -1 ? rawName : rawName.sublist(0, end);
    return String.fromCharCodes(slice);
  }

  /// Parses the RAR 4.x extended time field (`LHD_EXTTIME`) and returns a
  /// record containing modification time, creation time, and last-access time.
  /// Mirrors `Archive::ReadExt` / the `LHD_EXTTIME` branch in `arcread.cpp`.
  ///
  /// Loop index mapping:
  ///   0 → mtime (uses the DOS [fileTime] as base, no extra 4-byte field)
  ///   1 → ctime
  ///   2 → atime
  ///   3 → archive time (skipped — neoasis does not track archive-level time)
  _ExtTime15 _parseExtTime(RawReader raw, int fileTime, DateTime base) {
    final extFlags = raw.get2();
    var mtime = base;
    DateTime? ctime;
    DateTime? atime;
    for (var i = 0; i < 4; i++) {
      final rmode = (extFlags >> ((3 - i) * 4)) & 0xf;
      // Index 3 (archive time) is unused.
      if ((rmode & 8) == 0 || i == 3) {
        continue;
      }
      final dosTime = i == 0 ? fileTime : raw.get4();
      var dt = dosTimeToDateTime(dosTime);
      if ((rmode & 4) != 0) {
        dt = dt.add(const Duration(seconds: 1));
      }
      var reminder = 0;
      final count = rmode & 3;
      for (var j = 0; j < count; j++) {
        final curByte = raw.get1();
        reminder |= curByte << ((j + 3 - count) * 8);
      }
      // reminder is in units of 100 ns; convert to microseconds.
      final us = (reminder * 100) ~/ 1000;
      final precise = dt.add(Duration(microseconds: us));
      if (i == 0) {
        mtime = precise;
      } else if (i == 1) {
        ctime = precise;
      } else if (i == 2) {
        atime = precise;
      }
    }
    return _ExtTime15(mtime: mtime, ctime: ctime, atime: atime);
  }

  // ---------------------------------------------------------------------
  // RAR 5.0 block reading.
  // ---------------------------------------------------------------------

  Future<_BlockHeader?> _readHeader50() async {
    // If the archive uses header encryption (-hp), after the HEAD_CRYPT block
    // each subsequent header is prefixed with a 16-byte IV and the header
    // data itself is AES-256-CBC encrypted. Mirror `Archive::ReadHeader50`.
    AesCbcDecryptor? decryptor;
    if (_encrypted && _blockPos > _sfxSize + sizofMarkHead5) {
      if (_password == null) {
        throw const UnrarException(
            'Archive headers are encrypted: supply a password');
      }
      // Read per-header 16-byte initialization vector.
      final ivBytes = await _readExact(sizeInitV);
      if (ivBytes.length != sizeInitV) {
        return null;
      }
      // Build decryptor using the archive-level derived key + this header's IV.
      if (_rar5HeaderDecryptor == null) {
        throw const UnrarException(
            'HEAD_CRYPT block not found before encrypted header');
      }
      // Re-initialise with the per-header IV (the key stays the same).
      decryptor = AesCbcDecryptor(_rar5HeaderDecryptor!.aes, ivBytes);
    }

    final raw = RawReader(_source, decryptor: decryptor);
    if (await raw.read(sizofShortBlockHead5) < sizofShortBlockHead5) {
      return null;
    }

    final head = _BlockHeader();
    head.headCrc = raw.get4();
    final sizeBytes = raw.getVSize(4);
    final blockSize = raw.getV();

    if (blockSize == 0 || sizeBytes == 0) {
      _brokenHeader = true;
      return null;
    }

    final sizeToRead = blockSize - (sizofShortBlockHead5 - sizeBytes - 4);
    final headerSize = 4 + sizeBytes + blockSize;

    if (sizeToRead < 0 || headerSize < sizofShortBlockHead5) {
      _brokenHeader = true;
      return null;
    }

    // Only read more bytes if the buffer does not already cover the full header.
    // (With encrypted headers the first aligned read may have over-buffered.)
    if (raw.size < headerSize) {
      await raw.read(sizeToRead);
    }
    if (raw.size < headerSize) {
      return null; // Unexpected end of archive.
    }

    final headerCrc = raw.getCRC50(upTo: headerSize);

    head.type = _mapHeaderType50(raw.getV());
    head.flags = raw.getV();
    head.skipIfUnknown = (head.flags & hflSkipIfUnknown) != 0;
    head.headSize = headerSize;

    if (head.headCrc != headerCrc) {
      _brokenHeader = true;
    }

    var extraSize = 0;
    if ((head.flags & hflExtra) != 0) {
      extraSize = raw.getV();
      if (extraSize >= head.headSize) {
        _brokenHeader = true;
        return null;
      }
    }

    var dataSize = 0;
    if ((head.flags & hflData) != 0) {
      dataSize = raw.getV();
    }

    _nextBlockPos = (_blockPos + head.headSize) & 0xFFFFFFFFFFFFFFFF;
    _nextBlockPos = (_nextBlockPos + dataSize) & 0xFFFFFFFFFFFFFFFF;
    head.dataOffset = _blockPos + head.headSize;

    // For encrypted RAR 5.0 headers (mirrors `RawRead` crypt-aligned reads),
    // the physical bytes consumed from the source are:
    //   sizeInitV (IV) + alignedUp(headerSize) + dataSize
    // rather than just headerSize + dataSize.
    if (decryptor != null) {
      final alignedHead = (head.headSize + 15) & ~15;
      _nextBlockPos = _blockPos + sizeInitV + alignedHead + dataSize;
      head.dataOffset = _blockPos + sizeInitV + alignedHead;
    }

    switch (head.type) {
      case HeaderType.headCrypt:
        _encrypted = true;
        _info.encrypted = true;
        _parseCryptHead50(raw);
        break;
      case HeaderType.headMain:
        _parseMainHeader50(raw);
        if (extraSize != 0) {
          raw.skip(extraSize);
        }
        break;
      case HeaderType.headFile:
      case HeaderType.headService:
        head.dataSize = dataSize;
        head.entry = _parseFileHeader50(
          raw,
          head,
          extraSize: extraSize,
          isService: head.type == HeaderType.headService,
        );
        break;
      case HeaderType.headEndArc:
      default:
        break;
    }

    return head;
  }

  /// Parses the body of a RAR 5.0 `HEAD_CRYPT` block (archive encryption
  /// header), mirroring the `case HEAD_CRYPT` branch in `ReadHeader50`.
  ///
  /// If a password is available, derives the AES-256 key and stores it in
  /// [_rar5HeaderDecryptor] so subsequent header blocks can be decrypted.
  void _parseCryptHead50(RawReader raw) {
    final cryptVersion = raw.getV();
    if (cryptVersion > 0) {
      return; // Unknown encryption version; ignore.
    }
    final encFlags = raw.getV();
    _rar5UsePswCheck = (encFlags & chflCryptPswCheck) != 0;
    _rar5CryptLg2 = raw.get1();
    if (_rar5CryptLg2 > 24) {
      return;
    }
    _rar5CryptSalt = raw.getB(sizeSalt50);
    List<int>? pswCheckStored;
    if (_rar5UsePswCheck) {
      pswCheckStored = raw.getB(sizePswCheck);
      final csum = raw.getB(4);
      // Verify the pswcheck checksum (SHA-256 of pswCheck, first 4 bytes).
      final digest = sha256(pswCheckStored);
      if (digest[0] != csum[0] ||
          digest[1] != csum[1] ||
          digest[2] != csum[2] ||
          digest[3] != csum[3]) {
        _rar5UsePswCheck = false;
      } else {
        _rar5PswCheck = pswCheckStored;
      }
    }

    // Derive the archive-level header key if we have a password.
    if (_password != null && _rar5CryptSalt != null) {
      final pwd = _password;
      final kdf = kdf5(pwd, _rar5CryptSalt!, _rar5CryptLg2);
      // Validate password via pswCheck if available.
      if (_rar5UsePswCheck && _rar5PswCheck != null) {
        final pswCheck = _rar5PswCheck;
        final computed = foldPswCheck(kdf.pswCheckValue);
        for (var i = 0; i < sizePswCheck; i++) {
          if (computed[i] != pswCheck![i]) {
            throw const UnrarException(
                'Wrong password for encrypted archive headers');
          }
        }
      }
      // Store a "template" decryptor holding the key. The per-header IV will
      // be injected in _readHeader50 using decryptor.aes.
      _rar5HeaderDecryptor = AesCbcDecryptor(
          Aes.withKey(Uint8List.fromList(kdf.key)),
          List<int>.filled(sizeInitV, 0));
    }
  }

  void _parseMainHeader50(RawReader raw) {
    _info.reset();
    final arcFlags = raw.getV();
    _info.volume = (arcFlags & mhflVolume) != 0;
    _info.solid = (arcFlags & mhflSolid) != 0;
    _info.locked = (arcFlags & mhflLock) != 0;
    _info.protected = (arcFlags & mhflProtect) != 0;
    _info.signed = false; // RAR 5.0 never reports a signature (arcread.cpp).
    _info.newNumbering = true;
    if ((arcFlags & mhflVolNumber) != 0) {
      _info.volNumber = raw.getV();
    } else {
      _info.volNumber = 0;
    }
    _info.firstVolume = _info.volume && _info.volNumber == 0;
  }

  ArchiveEntry? _parseFileHeader50(
    RawReader raw,
    _BlockHeader head, {
    required int extraSize,
    required bool isService,
  }) {
    final fileFlags = raw.getV();
    var unpSize = raw.getV();
    final unknownUnpSize = (fileFlags & fhflUnpUnknown) != 0;
    if (unknownUnpSize) {
      unpSize = int64Ndf;
    }
    final fileAttr = raw.getV();

    DateTime? modifiedTime;
    if ((fileFlags & fhflUTime) != 0) {
      modifiedTime = unixTimeToDateTime(raw.get4());
    }

    var fileCrc = 0;
    if ((fileFlags & fhflCrc32) != 0) {
      fileCrc = raw.get4();
    }

    final compInfo = raw.getV();
    final method = (compInfo >> 7) & 7;
    final unpVerRaw = compInfo & 0x3f;
    var unpVer = verUnknown;
    if (unpVerRaw == 0) {
      unpVer = verPack5;
    } else if (unpVerRaw == 1) {
      unpVer = verPack7;
    }

    final hostOs = raw.getV();
    final nameSize = raw.getV();

    final readNameSize = nameSize < maxPathSize ? nameSize : maxPathSize;
    final nameBytes = raw.getB(readNameSize);
    final end = nameBytes.indexOf(0);
    final slice = end == -1 ? nameBytes : nameBytes.sublist(0, end);
    final name = utf8.decode(slice, allowMalformed: true);

    if (isService) {
      // A "CMT" sub-header marks the archive as having a comment.
      if (name.toUpperCase() == 'CMT') {
        _info.comment = true;
      }
      return null;
    }

    final isDir = (fileFlags & fhflDirectory) != 0;
    var windowSize = 0;
    // The mask uses the raw unpack version (0 for RAR 5.0, 1 for RAR 7.0),
    // not the parsed [verPack5]/[verPack7] values.
    if (!isDir && unpVerRaw <= 1) {
      windowSize =
          0x20000 << ((compInfo >> 10) & (unpVerRaw == 0 ? 0x0f : 0x1f));
    }

    final extra50 =
        extraSize != 0 ? _processExtra50(raw, extraSize, head.headSize) : null;
    final cryptInfo = extra50?.cryptInfo;
    final isEncrypted = cryptInfo != null;

    return ArchiveEntry(
      name: name,
      packSize: head.dataSize,
      unpSize: unpSize,
      isDirectory: isDir,
      isEncrypted: isEncrypted,
      isSolid: (compInfo & fciSolid) != 0,
      splitBefore: (head.flags & hflSplitBefore) != 0,
      splitAfter: (head.flags & hflSplitAfter) != 0,
      crc32: fileCrc,
      modifiedTime: extra50?.mtime ?? modifiedTime,
      createdTime: extra50?.ctime,
      accessedTime: extra50?.atime,
      method: method,
      unpVer: unpVer,
      hostOs: hostOs,
      fileAttr: fileAttr,
      flags: head.flags,
      windowSize: windowSize,
      unknownUnpSize: unknownUnpSize,
      isService: false,
      hostSystemType: hostOs == host5Unix
          ? HostSystemType.hsysUnix
          : hostOs == host5Windows
              ? HostSystemType.hsysWindows
              : HostSystemType.hsysUnknown,
      cryptInfo: cryptInfo,
      redirectType: extra50?.redirectType ?? FileSystemRedirect.fsRedirNone,
      redirectTarget: extra50?.redirectTarget,
      redirectTargetIsDir: extra50?.redirectTargetIsDir ?? false,
      unixOwner: extra50?.unixOwner,
      hashType: extra50?.hashType ?? FileHashType.none,
      blake2Digest: extra50?.blake2Digest,
    );
  }

  /// Parses the RAR 5.0 header extra area, mirroring `ProcessExtra50`.
  ///
  /// [headerSize] is the logical header size (not the block-aligned physical
  /// size), so the extra area is correctly located even when the buffer is
  /// larger than the header (e.g. when AES-CBC zero-padding is present).
  _Extra50Result? _processExtra50(
      RawReader raw, int extraSize, int headerSize) {
    final extraStart = headerSize - extraSize;
    if (extraStart < raw.readPos || extraStart < 0) {
      return null;
    }
    raw.setPos(extraStart);
    var result = const _Extra50Result();
    while (raw.dataLeft >= 2) {
      final fieldSize = raw.getV();
      if (fieldSize <= 0 || raw.dataLeft == 0 || fieldSize > raw.dataLeft) {
        break;
      }
      final nextPos = raw.readPos + fieldSize;
      final fieldType = raw.getV();
      if (nextPos - raw.readPos < 0) {
        break;
      }
      switch (fieldType) {
        case fhExtraCrypt:
          final crypt = _parseFhExtraCrypt(raw, nextPos);
          if (crypt != null) result = result.withCrypt(crypt);
        case fhExtraHash:
          final hash = _parseFhExtraHash(raw, nextPos);
          if (hash != null) result = result.withHash(hash);
        case fhExtraHtime:
          final times = _parseFhExtraHtime(raw, fieldSize);
          if (times != null) result = result.withTimes(times);
        case fhExtraRedir:
          final redir = _parseFhExtraRedir(raw, nextPos);
          if (redir != null) result = result.withRedir(redir);
        case fhExtraUowner:
          final owner = _parseFhExtraUowner(raw, nextPos);
          if (owner != null) result = result.withOwner(owner);
        default:
          break;
      }
      raw.setPos(nextPos);
    }
    return result;
  }

  /// Parses a `FHEXTRA_CRYPT` record body (RAR 5.0).
  CryptInfo? _parseFhExtraCrypt(RawReader raw, int fieldEnd) {
    final encVersion = raw.getV();
    if (encVersion > 0) {
      return null; // Unknown encryption version.
    }
    final flags = raw.getV();
    final lg2 = raw.get1();
    if (lg2 > 24) {
      return null;
    }
    final salt = raw.getB(sizeSalt50);
    final iv = raw.getB(sizeInitV);
    final usePswCheck = (flags & chflCryptPswCheck) != 0;
    final useHashKey = (flags & fhExtraCryptHashMac) != 0;
    List<int>? pswCheck;
    var validPswCheck = false;
    if (usePswCheck && raw.readPos + sizePswCheck + 4 <= fieldEnd) {
      final stored = raw.getB(sizePswCheck);
      final csum = raw.getB(4);
      final digest = sha256(stored);
      if (digest[0] == csum[0] &&
          digest[1] == csum[1] &&
          digest[2] == csum[2] &&
          digest[3] == csum[3]) {
        pswCheck = stored;
        validPswCheck = true;
      }
    }
    return CryptInfo(
      isRar4: false,
      salt: salt,
      iv: iv,
      lg2Count: lg2,
      pswCheck: pswCheck,
      usePswCheck: validPswCheck,
      useHashKey: useHashKey,
    );
  }

  /// Parses a `FHEXTRA_HASH` record body, mirroring `ProcessExtra50` case
  /// `FHEXTRA_HASH`. Returns a [_HashResult] or `null` on bad data.
  _HashResult? _parseFhExtraHash(RawReader raw, int fieldEnd) {
    final type = raw.getV();
    switch (type) {
      case fhExtraHashBlake2:
        if (raw.readPos + blake2DigestSize > fieldEnd) {
          return null;
        }
        return _HashResult(
          type: FileHashType.blake2,
          digest: raw.getB(blake2DigestSize),
        );
      default:
        return null;
    }
  }

  /// Parses a `FHEXTRA_HTIME` record, mirroring `ProcessExtra50` case
  /// `FHEXTRA_HTIME`. Returns a [_TimesResult] or `null` on bad data.
  _TimesResult? _parseFhExtraHtime(RawReader raw, int fieldSize) {
    if (fieldSize < 1) return null;
    final flags = raw.get1();
    final isUnix = (flags & fhExtraHtimeUnixTime) != 0;
    DateTime? mtime, ctime, atime;

    if ((flags & fhExtraHtimeMtime) != 0) {
      mtime = isUnix
          ? unixTimeToDateTime(raw.get4())
          : winFileTimeToDateTime(raw.get8());
    }
    if ((flags & fhExtraHtimeCtime) != 0) {
      ctime = isUnix
          ? unixTimeToDateTime(raw.get4())
          : winFileTimeToDateTime(raw.get8());
    }
    if ((flags & fhExtraHtimeAtime) != 0) {
      atime = isUnix
          ? unixTimeToDateTime(raw.get4())
          : winFileTimeToDateTime(raw.get8());
    }
    // Nanosecond adjustment (Unix only).
    if (isUnix && (flags & fhExtraHtimeUnixNs) != 0) {
      if (mtime != null) {
        final ns = raw.get4() & 0x3fffffff;
        if (ns < 1000000000) {
          mtime = mtime.add(Duration(microseconds: ns ~/ 1000));
        }
      }
      if (ctime != null) {
        final ns = raw.get4() & 0x3fffffff;
        if (ns < 1000000000) {
          ctime = ctime.add(Duration(microseconds: ns ~/ 1000));
        }
      }
      if (atime != null) {
        final ns = raw.get4() & 0x3fffffff;
        if (ns < 1000000000) {
          atime = atime.add(Duration(microseconds: ns ~/ 1000));
        }
      }
    }
    return _TimesResult(mtime: mtime, ctime: ctime, atime: atime);
  }

  /// Parses a `FHEXTRA_REDIR` record, mirroring `ProcessExtra50` case
  /// `FHEXTRA_REDIR`.
  _RedirResult? _parseFhExtraRedir(RawReader raw, int fieldEnd) {
    final typeV = raw.getV();
    if (typeV < 0 || typeV > FileSystemRedirect.values.length) return null;
    final redirectType = FileSystemRedirect.values.firstWhere(
        (e) => e.value == typeV,
        orElse: () => FileSystemRedirect.fsRedirNone);
    final flags = raw.getV();
    final isDir = (flags & fhExtraRedirDir) != 0;
    final nameSize = raw.getV();
    if (nameSize <= 0 || nameSize > fieldEnd - raw.readPos) return null;
    final nameBytes = raw.getB(nameSize);
    final target = utf8.decode(nameBytes, allowMalformed: true);
    return _RedirResult(type: redirectType, target: target, isDir: isDir);
  }

  /// Parses a `FHEXTRA_UOWNER` record, mirroring `ProcessExtra50` case
  /// `FHEXTRA_UOWNER`.
  UnixOwnerInfo? _parseFhExtraUowner(RawReader raw, int fieldEnd) {
    final flags = raw.getV();
    String? ownerName, groupName;
    int? ownerId, groupId;
    if ((flags & fhExtraUownerUname) != 0) {
      final len = raw.getV();
      ownerName = String.fromCharCodes(raw.getB(len));
    }
    if ((flags & fhExtraUownerGname) != 0) {
      final len = raw.getV();
      groupName = String.fromCharCodes(raw.getB(len));
    }
    if ((flags & fhExtraUownerNumUid) != 0) {
      ownerId = raw.getV();
    }
    if ((flags & fhExtraUownerNumGid) != 0) {
      groupId = raw.getV();
    }
    if (ownerName == null &&
        groupName == null &&
        ownerId == null &&
        groupId == null) {
      return null;
    }
    return UnixOwnerInfo(
      ownerName: ownerName,
      groupName: groupName,
      ownerId: ownerId,
      groupId: groupId,
    );
  }

  // ---------------------------------------------------------------------
  // Signature and header type mapping.
  // ---------------------------------------------------------------------
  RarFormat _isSignature(List<int> d, int offset, int size) {
    if (size >= 1 && d[offset] == 0x52) {
      if (size >= 4 &&
          d[offset + 1] == 0x45 &&
          d[offset + 2] == 0x7e &&
          d[offset + 3] == 0x5e) {
        return RarFormat.rarFmt14;
      }
      if (size >= 7 &&
          d[offset + 1] == 0x61 &&
          d[offset + 2] == 0x72 &&
          d[offset + 3] == 0x21 &&
          d[offset + 4] == 0x1a &&
          d[offset + 5] == 0x07) {
        final b6 = d[offset + 6];
        if (b6 == 0) {
          return RarFormat.rarFmt15;
        }
        if (b6 == 1) {
          return RarFormat.rarFmt50;
        }
        if (b6 > 1 && b6 < 5) {
          return RarFormat.rarFmtFuture;
        }
      }
    }
    return RarFormat.rarFmtNone;
  }

  int _findSignature(List<int> data) {
    for (var i = 0; i < data.length; i++) {
      if (data[i] == 0x52 &&
          _isSignature(data, i, data.length - i) != RarFormat.rarFmtNone) {
        return i;
      }
    }
    return -1;
  }

  HeaderType _mapHeaderType15(int type) {
    switch (type) {
      case 0x73:
        return HeaderType.headMain;
      case 0x74:
        return HeaderType.headFile;
      case 0x75:
        return HeaderType.head3Cmt;
      case 0x76:
        return HeaderType.head3Av;
      case 0x77:
        return HeaderType.head3OldService;
      case 0x78:
        return HeaderType.head3Protect;
      case 0x79:
        return HeaderType.head3Sign;
      case 0x7a:
        return HeaderType.headService;
      case 0x7b:
        return HeaderType.headEndArc;
      default:
        return HeaderType.headUnknown;
    }
  }

  HeaderType _mapHeaderType50(int type) {
    switch (type) {
      case 0x00:
        return HeaderType.headMark;
      case 0x01:
        return HeaderType.headMain;
      case 0x02:
        return HeaderType.headFile;
      case 0x03:
        return HeaderType.headService;
      case 0x04:
        return HeaderType.headCrypt;
      case 0x05:
        return HeaderType.headEndArc;
      default:
        return HeaderType.headUnknown;
    }
  }
}

// ---------------------------------------------------------------------------
// Private result types for _processExtra50
// ---------------------------------------------------------------------------

class _TimesResult {
  const _TimesResult({this.mtime, this.ctime, this.atime});
  final DateTime? mtime;
  final DateTime? ctime;
  final DateTime? atime;
}

class _RedirResult {
  const _RedirResult(
      {required this.type, required this.target, required this.isDir});
  final FileSystemRedirect type;
  final String target;
  final bool isDir;
}

class _HashResult {
  const _HashResult({required this.type, required this.digest});
  final FileHashType type;
  final List<int> digest;
}

/// Aggregates all extra fields parsed from a single `FHEXTRA_*` area.
class _Extra50Result {
  const _Extra50Result({
    this.cryptInfo,
    this.mtime,
    this.ctime,
    this.atime,
    this.redirectType = FileSystemRedirect.fsRedirNone,
    this.redirectTarget,
    this.redirectTargetIsDir = false,
    this.unixOwner,
    this.hashType = FileHashType.none,
    this.blake2Digest,
  });

  final CryptInfo? cryptInfo;
  final DateTime? mtime;
  final DateTime? ctime;
  final DateTime? atime;
  final FileSystemRedirect redirectType;
  final String? redirectTarget;
  final bool redirectTargetIsDir;
  final UnixOwnerInfo? unixOwner;
  final FileHashType hashType;
  final List<int>? blake2Digest;

  _Extra50Result withCrypt(CryptInfo c) => _Extra50Result(
      cryptInfo: c,
      mtime: mtime,
      ctime: ctime,
      atime: atime,
      redirectType: redirectType,
      redirectTarget: redirectTarget,
      redirectTargetIsDir: redirectTargetIsDir,
      unixOwner: unixOwner,
      hashType: hashType,
      blake2Digest: blake2Digest);

  _Extra50Result withTimes(_TimesResult t) => _Extra50Result(
      cryptInfo: cryptInfo,
      mtime: t.mtime ?? mtime,
      ctime: t.ctime ?? ctime,
      atime: t.atime ?? atime,
      redirectType: redirectType,
      redirectTarget: redirectTarget,
      redirectTargetIsDir: redirectTargetIsDir,
      unixOwner: unixOwner,
      hashType: hashType,
      blake2Digest: blake2Digest);

  _Extra50Result withRedir(_RedirResult r) => _Extra50Result(
      cryptInfo: cryptInfo,
      mtime: mtime,
      ctime: ctime,
      atime: atime,
      redirectType: r.type,
      redirectTarget: r.target,
      redirectTargetIsDir: r.isDir,
      unixOwner: unixOwner,
      hashType: hashType,
      blake2Digest: blake2Digest);

  _Extra50Result withOwner(UnixOwnerInfo o) => _Extra50Result(
      cryptInfo: cryptInfo,
      mtime: mtime,
      ctime: ctime,
      atime: atime,
      redirectType: redirectType,
      redirectTarget: redirectTarget,
      redirectTargetIsDir: redirectTargetIsDir,
      unixOwner: o,
      hashType: hashType,
      blake2Digest: blake2Digest);

  _Extra50Result withHash(_HashResult h) => _Extra50Result(
      cryptInfo: cryptInfo,
      mtime: mtime,
      ctime: ctime,
      atime: atime,
      redirectType: redirectType,
      redirectTarget: redirectTarget,
      redirectTargetIsDir: redirectTargetIsDir,
      unixOwner: unixOwner,
      hashType: h.type,
      blake2Digest: h.digest);
}

/// Return value of [ArchiveReader._parseExtTime], carrying the three RAR 4.x
/// extended timestamps (modification, creation, last-access).
class _ExtTime15 {
  const _ExtTime15({required this.mtime, this.ctime, this.atime});
  final DateTime mtime;
  final DateTime? ctime;
  final DateTime? atime;
}
