import 'dart:convert';
import 'dart:typed_data';

import 'archive_entry.dart';
import 'archive_info.dart';
import 'byte_source.dart';
import 'enc_name.dart';
import 'header_constants.dart';
import 'rar_time.dart';
import 'raw_reader.dart';
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

  bool skipIfUnknown = false;

  /// Parsed entry for HEAD_FILE blocks.
  ArchiveEntry? entry;
}

/// Reads archive blocks sequentially from a [ByteSource], ported from the
/// RARLAB UnRAR `Archive` class (`arcread.cpp`, `archive.cpp`).
///
/// Supports RAR 4.x (RAR 1.5 format, `ReadHeader15`) and RAR 5.0
/// (`ReadHeader50`) block layouts. Parsing is limited to the main and file
/// headers; extra fields, encrypted headers and recovery records are future
/// milestones.
class ArchiveReader {
  ArchiveReader(this._source);

  final ByteSource _source;

  RarFormat _format = RarFormat.rarFmtNone;
  final ArchiveInfo _info = ArchiveInfo();
  bool _encrypted = false;
  bool _brokenHeader = false;
  int _sfxSize = 0;
  bool _initialized = false;

  // CurBlockPos / NextBlockPos in the C code.
  int _blockPos = 0;
  int _nextBlockPos = 0;

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
      throw const UnrarException(
          'Encrypted archive headers are not supported yet');
    }

    if (!mainFound) {
      throw const UnrarFormatException('Main archive header is missing');
    }

    if (_brokenHeader) {
      throw const UnrarHeaderException('Main archive header is corrupt');
    }
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

  // ---------------------------------------------------------------------
  // RAR 4.x (RAR 1.5 format) block reading.
  // ---------------------------------------------------------------------

  Future<_BlockHeader?> _readHeader15() async {
    final raw = RawReader(_source);
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

    if ((head.flags & lhdSalt) != 0) {
      raw.skip(sizeSalt30);
    }

    var modifiedTime = dosTimeToDateTime(fileTime);
    if ((head.flags & lhdExtTime) != 0) {
      modifiedTime = _parseExtTime(raw, fileTime, modifiedTime);
    }

    if (isService) {
      return null;
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
    final raw = RawReader(_source);
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

    await raw.read(sizeToRead);
    if (raw.size < headerSize) {
      return null; // Unexpected end of archive.
    }

    final headerCrc = raw.getCRC50();

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

    switch (head.type) {
      case HeaderType.headCrypt:
        _encrypted = true;
        _info.encrypted = true;
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
          isService: head.type == HeaderType.headService,
        );
        if (extraSize != 0) {
          raw.skip(extraSize);
        }
        break;
      case HeaderType.headEndArc:
      default:
        break;
    }

    return head;
  }

  void _parseMainHeader50(RawReader raw) {
    _info.reset();
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
    if (!isDir && unpVer <= 1) {
      windowSize =
          0x20000 << ((compInfo >> 10) & (unpVer == verPack5 ? 0x0f : 0x1f));
    }

    return ArchiveEntry(
      name: name,
      packSize: head.dataSize,
      unpSize: unpSize,
      isDirectory: isDir,
      isEncrypted: false,
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
