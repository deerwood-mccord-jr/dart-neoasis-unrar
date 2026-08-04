import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'aes.dart';
import 'archive_entry.dart';
import 'archive_info.dart';
import 'byte_source.dart';
import 'enc_name.dart';
import 'header_constants.dart';
import 'kdf3.dart';
import 'kdf5.dart';
import 'rar_time.dart';
import 'raw_reader.dart';
import 'sha256.dart';
import 'unpacker.dart';
import 'unrar_error.dart';

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
}

/// Reads archive blocks sequentially from a [ByteSource], ported from the
/// RARLAB UnRAR `Archive` class (`arcread.cpp`, `archive.cpp`).
///
/// Supports RAR 4.x (RAR 1.5 format, `ReadHeader15`) and RAR 5.0
/// (`ReadHeader50`) block layouts. Parsing is limited to the main and file
/// headers; encrypted headers require a password via [password].
class ArchiveReader {
  ArchiveReader(this._source, {String? password})
      : _password = password,
        _unpacker = Unpacker(_source);

  final ByteSource _source;

  /// Optional decryption password supplied by the caller.
  final String? _password;

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
      throw const UnrarFormatException(
          'RAR 1.4 archives are not supported yet');
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

  Future<void> close() => _source.close();

  /// Extracts every file entry in archive order, invoking [onFile] with each
  /// entry and its fully unpacked, CRC-verified bytes. Directories and
  /// service blocks are skipped. Throws [UnsupportedMethodException] for
  /// unsupported compression methods and [UnrarException] on CRC mismatches.
  Future<void> extractAll(
      FutureOr<void> Function(ArchiveEntry entry, Uint8List data) onFile) async {
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
    var ok = true;
    await extractAll((entry, data) {
      // CRC verification happens inside extractAll's unpack path.
    });
    if (_brokenHeader) {
      ok = false;
    }
    return ok;
  }

  Future<Uint8List> _unpackEntry(ArchiveEntry entry, _BlockHeader head) async {
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
    if (entry.splitBefore || entry.splitAfter) {
      throw const UnrarException(
          'Split entries (multi-volume files) are not supported yet');
    }
    return _unpacker.unpack(
      method: entry.method,
      packSize: head.dataSize,
      unpSize: entry.unpSize,
      unknownUnpSize: entry.unknownUnpSize,
      dataOffset: head.dataOffset,
      expectedCrc: entry.crc32,
      unpVer: entry.unpVer,
      windowSize: entry.windowSize,
      solid: entry.isSolid,
      password: _password,
      cryptInfo: entry.cryptInfo,
    );
  }

  Future<void> _seekToNext() => _source.seek(_nextBlockPos);

  Future<Uint8List> _readExact(int size) async {
    final buffer = <int>[];
    while (buffer.length < size) {
      final chunk = await _source.read(size - buffer.length);
      if (chunk.isEmpty) {
        break;
      }
      buffer.addAll(chunk);
    }
    return Uint8List.fromList(buffer);
  }

  Future<_BlockHeader?> _readHeader() async {
    _blockPos = await _source.position();
    switch (_format) {
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

    final raw = RawReader(_source, decryptor: needsDecrypt ? _rar3HeaderDecryptor : null);
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

    await raw.read(head.headSize - sizofShortBlockHead);

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
        break;
      case HeaderType.headEndArc:
        break;
      case HeaderType.head3Protect:
        head.dataSize = raw.get4();
        _nextBlockPos = (_nextBlockPos + head.dataSize) & 0xFFFFFFFFFFFFFFFF;
        break;
      default:
        if ((head.flags & longBlock) != 0) {
          _nextBlockPos = (_nextBlockPos + raw.get4()) & 0xFFFFFFFFFFFFFFFF;
        }
    }

    final headerCrc = raw.getCRC15();
    if (head.headCrc != headerCrc) {
      _brokenHeader = true;
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
    if ((head.flags & lhdExtTime) != 0) {
      modifiedTime = _parseExtTime(raw, fileTime, modifiedTime);
    }

    final isDir = (head.flags & lhdWindowMask) == lhdDirectory;
    final windowSize =
        isDir ? 0 : 0x10000 << ((head.flags & lhdWindowMask) >> 5);

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
      method: method,
      unpVer: unpVer,
      hostOs: hostOs,
      fileAttr: fileAttr,
      flags: head.flags,
      windowSize: windowSize,
      unknownUnpSize: unknownUnpSize,
      isService: false,
      hostSystemType: hostOs == hostUnix || hostOs == hostBeos
          ? HostSystemType.hsysUnix
          : hostOs < hostMax
              ? HostSystemType.hsysWindows
              : HostSystemType.hsysUnknown,
      cryptInfo: cryptInfo,
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

  /// Reads the RAR 4.x extended time field and returns the (possibly
  /// adjusted) modification time.
  DateTime _parseExtTime(RawReader raw, int fileTime, DateTime base) {
    final extFlags = raw.get2();
    var modified = base;
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
      if (i == 0) {
        // reminder is in units of 100 ns; convert to microseconds.
        final us = (reminder * 100) ~/ 1000;
        modified = dt.add(Duration(microseconds: us));
      }
      // ctime/atime (i == 1, 2) are not exposed by the entry model yet.
    }
    return modified;
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

  void _parseMainHeader50(RawReader raw) {    _info.reset();
    final arcFlags = raw.getV();
    _info.volume = (arcFlags & mhflVolume) != 0;
    _info.solid = (arcFlags & mhflSolid) != 0;
    _info.locked = (arcFlags & mhflLock) != 0;
    _info.protected = (arcFlags & mhflProtect) != 0;
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

    final cryptInfo = extraSize != 0 ? _processExtra50(raw, extraSize, head.headSize) : null;
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
      modifiedTime: modifiedTime,
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
    );
  }

  /// Parses the RAR 5.0 header extra area, mirroring `ProcessExtra50`, and
  /// returns a [CryptInfo] if a file encryption (`FHEXTRA_CRYPT`) record was
  /// present, or `null` otherwise.
  ///
  /// [headerSize] is the logical header size (not the block-aligned physical
  /// size), so the extra area is correctly located even when the buffer is
  /// larger than the header (e.g. when AES-CBC zero-padding is present).
  CryptInfo? _processExtra50(RawReader raw, int extraSize, int headerSize) {
    final extraStart = headerSize - extraSize;
    if (extraStart < raw.readPos || extraStart < 0) {
      return null;
    }
    raw.setPos(extraStart);
    CryptInfo? cryptInfo;
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
      if (fieldType == fhExtraCrypt) {
        cryptInfo = _parseFhExtraCrypt(raw, nextPos);
      }
      raw.setPos(nextPos);
    }
    return cryptInfo;
  }

  /// Parses a `FHEXTRA_CRYPT` record body (RAR 5.0), mirroring the
  /// `case FHEXTRA_CRYPT` block in `ProcessExtra50`.
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

  // ---------------------------------------------------------------------
  // Signature and header type mapping.
  // ---------------------------------------------------------------------

  RarFormat _isSignature(List<int> d, int offset, int size) {
    if (size >= 1 && d[offset] == 0x52) {
      if (size >= 4 && d[offset + 1] == 0x45 &&
          d[offset + 2] == 0x7e && d[offset + 3] == 0x5e) {
        return RarFormat.rarFmt14;
      }
      if (size >= 7 && d[offset + 1] == 0x61 && d[offset + 2] == 0x72 &&
          d[offset + 3] == 0x21 && d[offset + 4] == 0x1a &&
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
      case 0x7a:
        return HeaderType.headService;
      case 0x7b:
        return HeaderType.headEndArc;
      case 0x78:
        return HeaderType.head3Protect;
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
