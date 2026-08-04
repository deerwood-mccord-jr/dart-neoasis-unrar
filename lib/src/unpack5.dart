/// RAR 5.0 / 7.0 decompression constants (ported from `compress.hpp`
/// `PackDef` and `unpack.hpp`).
library;

import 'dart:typed_data';

import 'bit_input.dart';
import 'unrar_error.dart';

/// Maximum LZ match length that can be encoded even for short distances.
const int maxLzMatch = 0x1001;

/// Maximum incremented LZ match length (`MAX_INC_LZ_MATCH`).
const int maxIncLzMatch = maxLzMatch + 3;

/// Alphabet sizes for the RAR 5.0 Huffman tables.
const int nc = 306; // Literals and matches.
const int dcb = 64; // Base distance codes up to 4 GB.
const int dcx = 80; // Extended distance codes up to 1 TB.
const int ldc = 16; // Lower bits of distances.
const int rc = 44; // Repeating distances.
const int bc = 20; // Bit lengths of the Huffman table.
const int huffTableSizeB = nc + dcb + rc + ldc; // 430
const int huffTableSizeX = nc + dcx + rc + ldc; // 446
const int largestTableSize = 306;

const int maxQuickDecodeBits = 9;
const int maxUnpackFilters = 8192;
const int maxFilterBlockSize = 0x400000;
const int unpackMaxWrite = 0x400000;
const int minAllocSize = 0x40000;

/// RAR 5.0 filter types (from `compress.hpp`).
const int filterDelta = 0;
const int filterE8 = 1;
const int filterE8E9 = 2;
const int filterArm = 3;
const int filterNone = 8;

/// Huffman decode table, ported from the C `DecodeTable` struct.
class DecodeTable {
  int maxNum = 0;

  /// Left aligned start and upper limit codes for each bit length.
  final decodeLen = Uint32List(16);

  /// Start position in the code list for each bit length.
  final decodePos = Uint32List(16);

  /// Number of bits processed in quick mode.
  int quickBits = 0;

  /// Translates up to [quickBits] compressed bits to a bit length.
  final quickLen = Uint8List(1 << maxQuickDecodeBits);

  /// Translates up to [quickBits] compressed bits to an alphabet position.
  final quickNum = Uint16List(1 << maxQuickDecodeBits);

  /// Position in the code list to alphabet position.
  final decodeNum = Uint16List(largestTableSize);
}

/// A decoded data block header (ported from `UnpackBlockHeader`).
class _BlockHeader50 {
  int blockSize = -1;
  int blockBitSize = 0;
  int blockStart = 0;
  int headerSize = 0;
  bool lastBlockInFile = false;
  bool tablePresent = false;
}

/// The five Huffman tables used per data block (ported from
/// `UnpackBlockTables`).
class _BlockTables {
  final ld = DecodeTable(); // Literals.
  final dd = DecodeTable(); // Distances.
  final ldd = DecodeTable(); // Lower bits of distances.
  final rd = DecodeTable(); // Repeating distances.
  final bd = DecodeTable(); // Bit lengths in Huffman table.
}

/// A pending filter to be applied to the window before writing
/// (ported from `UnpackFilter`).
class _UnpackFilter {
  int type = 0;
  int channels = 0;
  bool nextWindow = false;
  int blockStart = 0;
  int blockLength = 0;
}

/// RAR 5.0 and 7.0 decompressor, ported from `unpack.cpp`, `unpackinline.cpp`
/// and `unpack50.cpp`.
///
/// The instance keeps the sliding window and match history across solid
/// files, so a single instance must be reused while iterating an archive's
/// entries. The full packed stream of one file is held in memory.
class Rar5Unpacker {
  Rar5Unpacker();

  BitInput _inp = BitInput();
  Uint8List? _window;
  int _maxWinSize = 0;

  final _blockHeader = _BlockHeader50();
  final _blockTables = _BlockTables();

  final _oldDist = List<int>.filled(4, -1);
  int _lastLength = 0;

  int _unpPtr = 0;
  int _prevPtr = 0;
  bool _firstWinDone = false;
  int _wrPtr = 0;
  int _writeBorder = 0;

  int _readTop = 0;
  int _readBorder = 0;

  final _filters = <_UnpackFilter>[];

  int _destUnpSize = 0;
  int _writtenFileSize = 0;
  bool _tablesRead5 = false;
  bool _extraDist = false;

  int _packedLength = 0;
  final _output = BytesBuilder();

  /// Unpacks [packed] into a new byte buffer of [unpSize] bytes.
  ///
  /// [solid] marks a file continuing a solid stream; the window and match
  /// history of the previous file are reused. Returns the unpacked bytes.
  Uint8List unpack5({
    required Uint8List packed,
    required int unpSize,
    required int windowSize,
    required bool solid,
    required bool extraDist,
  }) {
    _extraDist = extraDist;
    _initWin(windowSize, solid);
    _inp = BitInput.external(packed);
    _packedLength = packed.length;
    _destUnpSize = unpSize;
    _unpack5(solid);
    return _output.takeBytes();
  }

  /// Mirrors `Unpack::Init`.
  void _initWin(int winSize, bool solid) {
    if (winSize < minAllocSize) {
      winSize = minAllocSize;
    }
    // Mirrors the C `WinSize>Min(0x10000000000ULL,UNPACK_MAX_DICT)` guard
    // (UNPACK_MAX_DICT is 64 GB).
    if (winSize > 0x1000000000) {
      throw UnrarException('Unsupported window size $winSize');
    }
    if (!solid || _window == null) {
      _maxWinSize = winSize;
    }
    if (_window == null || _window!.length < _maxWinSize) {
      _window = Uint8List(_maxWinSize);
    }
  }

  /// Mirrors `Unpack::UnpInitData` plus `UnpInitData50`.
  void _unpInitData(bool solid) {
    if (!solid) {
      _oldDist[0] = _oldDist[1] = _oldDist[2] = _oldDist[3] = -1;
      _lastLength = 0;
      _unpPtr = _wrPtr = 0;
      _prevPtr = 0;
      _firstWinDone = false;
      _writeBorder = _maxWinSize < unpackMaxWrite ? _maxWinSize : unpackMaxWrite;
      _tablesRead5 = false;
    }
    _initFilters();
    _inp.initBitInput();
    _writtenFileSize = 0;
    _readTop = 0;
    _readBorder = 0;
    _blockHeader
      ..blockSize = -1
      ..blockBitSize = 0
      ..blockStart = 0
      ..headerSize = 0
      ..lastBlockInFile = false
      ..tablePresent = false;
  }

  void _initFilters() => _filters.clear();

  /// Mirrors `Unpack::WrapDown`. In C a `size_t` underflow wraps to a huge
  /// value and adding `MaxWinSize` wraps back into the window; in Dart the
  /// same underflow shows up as a negative value, so we add `MaxWinSize`.
  int _wrapDown(int pos) {
    if (pos < 0) {
      return pos + _maxWinSize;
    }
    if (pos >= _maxWinSize) {
      return pos;
    }
    return pos;
  }

  /// Mirrors `Unpack::WrapUp`.
  int _wrapUp(int pos) {
    if (pos >= _maxWinSize) {
      return pos - _maxWinSize;
    }
    return pos;
  }

  /// Mirrors `Unpack::UnpReadBuf`. In the external-buffer mode the full
  /// packed stream is already in memory, so there is nothing to read or
  /// relocate; only the block accounting is kept.
  bool _unpReadBuf() {
    final dataSize = _readTop - _inp.inAddr;
    if (dataSize < 0) {
      return false;
    }
    _blockHeader.blockSize -= _inp.inAddr - _blockHeader.blockStart;
    _readBorder = _readTop - 30;
    _blockHeader.blockStart = _inp.inAddr;
    if (_blockHeader.blockSize != -1) {
      final border = _blockHeader.blockStart + _blockHeader.blockSize - 1;
      if (border < _readBorder) {
        _readBorder = border;
      }
    }
    return true;
  }

  /// Mirrors `Unpack::Unpack5`.
  void _unpack5(bool solid) {
    _unpInitData(solid);
    _readTop = _packedLength;
    if (!_unpReadBuf()) {
      return;
    }
    // The first block of a file always carries its tables.
    if (!_readBlockHeader(_inp, _blockHeader) ||
        !_readTables(_inp, _blockHeader, _blockTables) ||
        !_tablesRead5) {
      return;
    }

    while (true) {
      _unpPtr = _wrapUp(_unpPtr);

      _firstWinDone = _firstWinDone || (_prevPtr > _unpPtr);
      _prevPtr = _unpPtr;

      if (_inp.inAddr >= _readBorder) {
        var fileDone = false;

        // A block holding only a Huffman table leaves us on the block border
        // right after reading it, so the 'while' re-checks.
        while (_inp.inAddr > _blockHeader.blockStart + _blockHeader.blockSize - 1 ||
            (_inp.inAddr == _blockHeader.blockStart + _blockHeader.blockSize - 1 &&
                _inp.inBit >= _blockHeader.blockBitSize)) {
          if (_blockHeader.lastBlockInFile) {
            fileDone = true;
            break;
          }
          if (!_readBlockHeader(_inp, _blockHeader) ||
              !_readTables(_inp, _blockHeader, _blockTables)) {
            return;
          }
        }
        if (fileDone || !_unpReadBuf()) {
          break;
        }
      }

      // WriteBorder == UnpPtr means we have MaxWinSize data ahead.
      if (_wrapDown(_writeBorder - _unpPtr) <= maxIncLzMatch &&
          _writeBorder != _unpPtr) {
        _unpWriteBuf();
        if (_writtenFileSize > _destUnpSize) {
          return;
        }
      }

      final mainSlot = decodeNumber(_inp, _blockTables.ld);
      if (mainSlot < 256) {
        _window![_unpPtr++] = mainSlot;
        continue;
      }
      if (mainSlot >= 262) {
        var length = _slotToLength(_inp, mainSlot - 262);

        var distance = 1;
        int dBits;
        final distSlot = decodeNumber(_inp, _blockTables.dd);
        if (distSlot < 4) {
          dBits = 0;
          distance += distSlot;
        } else {
          dBits = distSlot ~/ 2 - 1;
          distance += (2 | (distSlot & 1)) << dBits;
        }

        if (dBits > 0) {
          if (dBits >= 4) {
            if (dBits > 4) {
              // C falls back to getbits64() only for very large distances.
              if (dBits > 36) {
                distance += (_inp.getbits64() >> (68 - dBits)) << 4;
              } else {
                distance += (_inp.getbits32() >> (36 - dBits)) << 4;
              }
              _inp.addbits(dBits - 4);
            }
            distance += decodeNumber(_inp, _blockTables.ldd);
            // The 32-bit "distance can be 0 for multiples of 4 GB" correction
            // does not apply to Dart's 64-bit integers.
          } else {
            distance += _inp.getbits() >> (16 - dBits);
            _inp.addbits(dBits);
          }
        }

        if (distance > 0x100) {
          length++;
          if (distance > 0x2000) {
            length++;
            if (distance > 0x40000) {
              length++;
            }
          }
        }

        _insertOldDist(distance);
        _lastLength = length;
        _copyString(length, distance);
        continue;
      }
      if (mainSlot == 256) {
        final filter = _UnpackFilter();
        if (!_readFilter(_inp, filter) || !_addFilter(filter)) {
          break;
        }
        continue;
      }
      if (mainSlot == 257) {
        if (_lastLength != 0) {
          _copyString(_lastLength, _oldDist[0]);
        }
        continue;
      }
      if (mainSlot < 262) {
        final distNum = mainSlot - 258;
        var distance = _oldDist[distNum];
        for (var i = distNum; i > 0; i--) {
          _oldDist[i] = _oldDist[i - 1];
        }
        _oldDist[0] = distance;

        final length = _slotToLength(_inp, decodeNumber(_inp, _blockTables.rd));
        _lastLength = length;
        _copyString(length, distance);
        continue;
      }
    }
    _unpWriteBuf();
  }

  /// Mirrors `Unpack::SlotToLength`.
  int _slotToLength(BitInput inp, int slot) {
    var length = 2;
    int lBits;
    if (slot < 8) {
      lBits = 0;
      length += slot;
    } else {
      lBits = slot ~/ 4 - 1;
      length += (4 | (slot & 3)) << lBits;
    }
    if (lBits > 0) {
      length += inp.getbits() >> (16 - lBits);
      inp.addbits(lBits);
    }
    return length;
  }

  /// Mirrors `Unpack::InsertOldDist`.
  void _insertOldDist(int distance) {
    _oldDist[3] = _oldDist[2];
    _oldDist[2] = _oldDist[1];
    _oldDist[1] = _oldDist[0];
    _oldDist[0] = distance;
  }

  /// Mirrors `Unpack::CopyString`.
  void _copyString(int length, int distance) {
    final window = _window!;
    var srcPtr = _unpPtr - distance;

    if (distance > _unpPtr) {
      srcPtr += _maxWinSize;

      if (distance > _maxWinSize || !_firstWinDone) {
        // Fill the area with zeroes, so the output does not depend on
        // previously extracted data and offsets stay valid.
        while (length-- > 0) {
          window[_unpPtr] = 0;
          _unpPtr = _wrapUp(_unpPtr + 1);
        }
        return;
      }
    }

    if (srcPtr < _maxWinSize - maxIncLzMatch &&
        _unpPtr < _maxWinSize - maxIncLzMatch) {
      // Fast path: far enough from the window ends to skip wrap checks.
      final start = _unpPtr;
      for (var i = 0; i < length; i++) {
        window[start + i] = window[srcPtr + i];
      }
      _unpPtr = start + length;
    } else {
      while (length-- > 0) {
        window[_unpPtr] = window[_wrapUp(srcPtr++)];
        _unpPtr = _wrapUp(_unpPtr + 1);
      }
    }
  }

  /// Mirrors `Unpack::ReadBlockHeader`.
  bool _readBlockHeader(BitInput inp, _BlockHeader50 header) {
    header.headerSize = 0;

    inp.addbits((8 - inp.inBit) & 7);

    final blockFlags = (inp.getbits() >> 8) & 0xff;
    inp.addbits(8);
    final byteCount = ((blockFlags >> 3) & 3) + 1; // Block size byte count.

    if (byteCount == 4) {
      return false;
    }

    header.headerSize = 2 + byteCount;
    header.blockBitSize = (blockFlags & 7) + 1;

    final savedCheckSum = (inp.getbits() >> 8) & 0xff;
    inp.addbits(8);

    var blockSize = 0;
    for (var i = 0; i < byteCount; i++) {
      blockSize += (inp.getbits() >> 8) << (i * 8);
      inp.addbits(8);
    }

    header.blockSize = blockSize;
    final checkSum =
        0x5a ^ blockFlags ^ blockSize ^ (blockSize >> 8) ^ (blockSize >> 16);
    if ((checkSum & 0xff) != savedCheckSum) {
      return false;
    }

    header.blockStart = inp.inAddr;

    final border = header.blockStart + header.blockSize - 1;
    if (border < _readBorder) {
      _readBorder = border;
    }

    header.lastBlockInFile = (blockFlags & 0x40) != 0;
    header.tablePresent = (blockFlags & 0x80) != 0;

    return true;
  }

  /// Mirrors `Unpack::ReadTables`.
  bool _readTables(BitInput inp, _BlockHeader50 header, _BlockTables tables) {
    if (!header.tablePresent) {
      return true;
    }

    final bitLength = Uint8List(bc);
    for (var i = 0; i < bc; i++) {
      var length = (inp.getbits() >> 12) & 0xff;
      inp.addbits(4);
      if (length == 15) {
        var zeroCount = (inp.getbits() >> 12) & 0xff;
        inp.addbits(4);
        if (zeroCount == 0) {
          bitLength[i] = 15;
        } else {
          zeroCount += 2;
          while (zeroCount-- > 0 && i < bitLength.length) {
            bitLength[i++] = 0;
          }
          i--;
        }
      } else {
        bitLength[i] = length;
      }
    }

    makeDecodeTables(bitLength, tables.bd, bc);

    final table = Uint8List(huffTableSizeX);
    final tableSize = _extraDist ? huffTableSizeX : huffTableSizeB;
    for (var i = 0; i < tableSize;) {
      final number = decodeNumber(inp, tables.bd);
      if (number < 16) {
        table[i] = number;
        i++;
      } else if (number < 18) {
        var n = 0;
        if (number == 16) {
          n = (inp.getbits() >> 13) + 3;
          inp.addbits(3);
        } else {
          n = (inp.getbits() >> 9) + 11;
          inp.addbits(7);
        }
        if (i == 0) {
          // "Repeat previous" is not allowed at the first position.
          return false;
        }
        while (n-- > 0 && i < tableSize) {
          table[i] = table[i - 1];
          i++;
        }
      } else {
        var n = 0;
        if (number == 18) {
          n = (inp.getbits() >> 13) + 3;
          inp.addbits(3);
        } else {
          n = (inp.getbits() >> 9) + 11;
          inp.addbits(7);
        }
        while (n-- > 0 && i < tableSize) {
          table[i++] = 0;
        }
      }
    }
    _tablesRead5 = true;
    makeDecodeTables(table.sublist(0, nc), tables.ld, nc);
    final dCodes = _extraDist ? dcx : dcb;
    makeDecodeTables(table.sublist(nc, nc + dCodes), tables.dd, dCodes);
    makeDecodeTables(
        table.sublist(nc + dCodes, nc + dCodes + ldc), tables.ldd, ldc);
    makeDecodeTables(
        table.sublist(nc + dCodes + ldc, nc + dCodes + ldc + rc), tables.rd, rc);
    return true;
  }

  /// Mirrors `Unpack::ReadFilterData`.
  int _readFilterData(BitInput inp) {
    final byteCount = (inp.getbits() >> 14) + 1;
    inp.addbits(2);

    var data = 0;
    for (var i = 0; i < byteCount; i++) {
      data += (inp.getbits() >> 8) << (i * 8);
      inp.addbits(8);
    }
    return data;
  }

  /// Mirrors `Unpack::ReadFilter`.
  bool _readFilter(BitInput inp, _UnpackFilter filter) {
    filter.blockStart = _readFilterData(inp);
    filter.blockLength = _readFilterData(inp);
    if (filter.blockLength > maxFilterBlockSize) {
      filter.blockLength = 0;
    }

    filter.type = inp.getbits() >> 13;
    inp.addbits(3);

    if (filter.type == filterDelta) {
      filter.channels = (inp.getbits() >> 11) + 1;
      inp.addbits(5);
    }

    return true;
  }

  /// Mirrors `Unpack::AddFilter`.
  bool _addFilter(_UnpackFilter filter) {
    if (_filters.length >= maxUnpackFilters) {
      _unpWriteBuf(); // Write data, apply and flush filters.
      if (_filters.length >= maxUnpackFilters) {
        _initFilters(); // Still too many filters, prevent excessive memory use.
      }
    }

    // A filter whose start lies in not-yet-written circular-dictionary data
    // is deferred to the next window block.
    filter.nextWindow = _wrPtr != _unpPtr &&
        _wrapDown(_wrPtr - _unpPtr) <= filter.blockStart;

    filter.blockStart = (filter.blockStart + _unpPtr) % _maxWinSize;
    _filters.add(filter);
    return true;
  }

  /// Mirrors `Unpack::UnpWriteBuf`.
  void _unpWriteBuf() {
    var writtenBorder = _wrPtr;
    final fullWriteSize = _wrapDown(_unpPtr - writtenBorder);
    var writeSizeLeft = fullWriteSize;
    var notAllFiltersProcessed = false;

    for (var i = 0; i < _filters.length; i++) {
      final flt = _filters[i];
      if (flt.type == filterNone) {
        continue;
      }
      if (flt.nextWindow) {
        if (_wrapDown(flt.blockStart - _wrPtr) <= fullWriteSize) {
          flt.nextWindow = false;
        }
        continue;
      }

      final blockStart = flt.blockStart;
      final blockLength = flt.blockLength;
      if (_wrapDown(blockStart - writtenBorder) < writeSizeLeft) {
        if (writtenBorder != blockStart) {
          _unpWriteArea(writtenBorder, blockStart);
          writtenBorder = blockStart;
          writeSizeLeft = _wrapDown(_unpPtr - writtenBorder);
        }

        if (blockLength <= writeSizeLeft) {
          if (blockLength > 0) {
            final blockEnd = _wrapUp(blockStart + blockLength);

            // Copy the filter input out of the window (which must stay
            // intact for future string matches).
            final mem = Uint8List(blockLength);
            if (blockStart < blockEnd || blockEnd == 0) {
              mem.setRange(0, blockLength, _window!, blockStart);
            } else {
              final firstPartLength = _maxWinSize - blockStart;
              mem.setRange(0, firstPartLength, _window!, blockStart);
              mem.setRange(firstPartLength, blockEnd + firstPartLength, _window!, 0);
            }

            final outMem = _applyFilter(mem, blockLength, flt);

            _filters[i].type = filterNone;

            if (outMem != null) {
              _output.add(outMem);
            }

            _writtenFileSize += blockLength;
            writtenBorder = blockEnd;
            writeSizeLeft = _wrapDown(_unpPtr - writtenBorder);
          }
        } else {
          // The filter intersects the window write border; postpone it.
          _wrPtr = writtenBorder;

          for (var j = i; j < _filters.length; j++) {
            if (_filters[j].type != filterNone) {
              _filters[j].nextWindow = false;
            }
          }

          notAllFiltersProcessed = true;
          break;
        }
      }
    }

    // Remove processed filters from the queue.
    var emptyCount = 0;
    for (var i = 0; i < _filters.length; i++) {
      if (emptyCount > 0) {
        _filters[i - emptyCount] = _filters[i];
      }
      if (_filters[i].type == filterNone) {
        emptyCount++;
      }
    }
    if (emptyCount > 0) {
      _filters.removeRange(_filters.length - emptyCount, _filters.length);
    }

    if (!notAllFiltersProcessed) {
      // Write the data left after the last filter.
      _unpWriteArea(writtenBorder, _unpPtr);
      _wrPtr = _unpPtr;
    }

    _writeBorder = _wrapUp(
        _unpPtr + (_maxWinSize < unpackMaxWrite ? _maxWinSize : unpackMaxWrite));

    if (_writeBorder == _unpPtr ||
        (_wrPtr != _unpPtr &&
            _wrapDown(_wrPtr - _unpPtr) < _wrapDown(_writeBorder - _unpPtr))) {
      _writeBorder = _wrPtr;
    }
  }

  /// Mirrors `Unpack::ApplyFilter`. Returns the filtered block, or `null`
  /// for unknown/invalid filter types (their data is dropped, as in C).
  Uint8List? _applyFilter(Uint8List data, int dataSize, _UnpackFilter flt) {
    final srcData = data;
    switch (flt.type) {
      case filterE8:
      case filterE8E9:
        final fileOffset = _writtenFileSize & 0xFFFFFFFF;
        const fileSize = 0x1000000;
        final cmpByte2 = flt.type == filterE8E9 ? 0xe9 : 0xe8;
        var curPos = 0;
        var dataPos = 0;
        while (curPos + 4 < dataSize) {
          final curByte = data[dataPos++];
          curPos++;
          if (curByte == 0xe8 || curByte == cmpByte2) {
            final offset = (curPos + fileOffset) % fileSize;
            final addr = _rawGet4(data, dataPos);

            // Check the 0x80000000 bit instead of comparing signedness.
            if ((addr & 0x80000000) != 0) {
              if (((addr + offset) & 0x80000000) == 0) {
                _rawPut4((addr + fileSize) & 0xFFFFFFFF, data, dataPos);
              }
            } else {
              if (((addr - fileSize) & 0x80000000) != 0) {
                _rawPut4((addr - offset) & 0xFFFFFFFF, data, dataPos);
              }
            }

            dataPos += 4;
            curPos += 4;
          }
        }
        return srcData;
      case filterArm:
        final fileOffset = _writtenFileSize & 0xFFFFFFFF;
        for (var curPos = 0; curPos + 3 < dataSize; curPos += 4) {
          if (data[curPos + 3] == 0xeb) {
            var offset = data[curPos] +
                data[curPos + 1] * 0x100 +
                data[curPos + 2] * 0x10000;
            offset -= (fileOffset + curPos) ~/ 4;
            data[curPos] = offset & 0xff;
            data[curPos + 1] = (offset >> 8) & 0xff;
            data[curPos + 2] = (offset >> 16) & 0xff;
          }
        }
        return srcData;
      case filterDelta:
        final channels = flt.channels;
        final dst = Uint8List(dataSize);

        // Bytes from the same channel are grouped into contiguous blocks;
        // place them back at their interleaving positions.
        var srcPos = 0;
        for (var curChannel = 0; curChannel < channels; curChannel++) {
          var prevByte = 0;
          for (var destPos = curChannel; destPos < dataSize; destPos += channels) {
            prevByte = (prevByte - data[srcPos++]) & 0xff;
            dst[destPos] = prevByte;
          }
        }
        return dst;
    }
    return null;
  }

  /// Mirrors `Unpack::UnpWriteArea` for a single contiguous window.
  void _unpWriteArea(int startPtr, int endPtr) {
    final window = _window!;
    if (endPtr < startPtr) {
      _unpWriteData(Uint8List.sublistView(window, startPtr, _maxWinSize),
          _maxWinSize - startPtr);
      _unpWriteData(Uint8List.sublistView(window, 0, endPtr), endPtr);
    } else {
      _unpWriteData(Uint8List.sublistView(window, startPtr, endPtr),
          endPtr - startPtr);
    }
  }

  /// Mirrors `Unpack::UnpWriteData`, capping at the destination size.
  void _unpWriteData(Uint8List data, int size) {
    if (_writtenFileSize >= _destUnpSize) {
      return;
    }
    var writeSize = size;
    final leftToWrite = _destUnpSize - _writtenFileSize;
    if (writeSize > leftToWrite) {
      writeSize = leftToWrite;
    }
    if (writeSize > 0) {
      _output.add(data.sublist(0, writeSize));
    }
    _writtenFileSize += size;
  }
}

int _rawGet4(Uint8List data, int offset) =>
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24);

void _rawPut4(int value, Uint8List data, int offset) {
  data[offset] = value & 0xff;
  data[offset + 1] = (value >> 8) & 0xff;
  data[offset + 2] = (value >> 16) & 0xff;
  data[offset + 3] = (value >> 24) & 0xff;
}

/// Mirrors `Unpack::DecodeNumber` (shared by the RAR 4.x and RAR 5.0
/// decompressors).
int decodeNumber(BitInput inp, DecodeTable dec) {
  // Left aligned 15-bit raw bit field.
  final bitField = inp.getbits() & 0xfffe;

  if (bitField < dec.decodeLen[dec.quickBits]) {
    final code = bitField >> (16 - dec.quickBits);
    inp.addbits(dec.quickLen[code]);
    return dec.quickNum[code];
  }

  // Detect the real bit length for the current code.
  var bits = 15;
  for (var i = dec.quickBits + 1; i < 15; i++) {
    if (bitField < dec.decodeLen[i]) {
      bits = i;
      break;
    }
  }

  inp.addbits(bits);

  final dist = bitField - dec.decodeLen[bits - 1];
  final shifted = dist >> (16 - bits);
  var pos = dec.decodePos[bits] + shifted;

  // Out of bounds safety check required for damaged archives. C relies on
  // unsigned wrap-around, which appears as a negative value in Dart.
  if (pos < 0 || pos >= dec.maxNum) {
    pos = 0;
  }

  return dec.decodeNum[pos];
}

/// Mirrors `Unpack::MakeDecodeTables` (shared by the RAR 4.x and RAR 5.0
/// decompressors).
void makeDecodeTables(Uint8List lengthTable, DecodeTable dec, int size) {
  dec.maxNum = size;

  final lengthCount = Uint32List(16);
  for (var i = 0; i < size; i++) {
    lengthCount[lengthTable[i] & 0xf]++;
  }
  lengthCount[0] = 0;

  for (var i = 0; i < size; i++) {
    dec.decodeNum[i] = 0;
  }
  dec.decodePos[0] = 0;
  dec.decodeLen[0] = 0;

  var upperLimit = 0;
  for (var i = 1; i < 16; i++) {
    upperLimit += lengthCount[i];
    final leftAligned = upperLimit << (16 - i);
    upperLimit *= 2;
    dec.decodeLen[i] = leftAligned;
    dec.decodePos[i] = dec.decodePos[i - 1] + lengthCount[i - 1];
  }

  final copyDecodePos = Uint32List.fromList(dec.decodePos);
  for (var i = 0; i < size; i++) {
    final curBitLength = lengthTable[i] & 0xf;
    if (curBitLength != 0) {
      final lastPos = copyDecodePos[curBitLength];
      dec.decodeNum[lastPos] = i;
      copyDecodePos[curBitLength]++;
    }
  }

  switch (size) {
    case nc:
      dec.quickBits = maxQuickDecodeBits;
      break;
    default:
      dec.quickBits = maxQuickDecodeBits > 3 ? maxQuickDecodeBits - 3 : 0;
  }

  final quickDataSize = 1 << dec.quickBits;
  var curBitLength = 1;
  for (var code = 0; code < quickDataSize; code++) {
    final bitField = code << (16 - dec.quickBits);

    while (curBitLength < 16 && bitField >= dec.decodeLen[curBitLength]) {
      curBitLength++;
    }
    dec.quickLen[code] = curBitLength;

    // Mirrors the C guard `CurBitLength<ASIZE(DecodePos)` before indexing
    // `DecodePos[CurBitLength]`, which is otherwise out of range when
    // [curBitLength] reaches 16 for unusual but valid tables.
    if (curBitLength < 16) {
      final dist = bitField - dec.decodeLen[curBitLength - 1];
      final shifted = dist >> (16 - curBitLength);
      final pos = dec.decodePos[curBitLength] + shifted;

      if (pos < size) {
        dec.quickNum[code] = dec.decodeNum[pos];
      } else {
        dec.quickNum[code] = 0;
      }
    } else {
      dec.quickNum[code] = 0;
    }
  }
}
