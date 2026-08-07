/// RAR 4.x decompression, ported from `unpack.cpp`, `unpack20.cpp`,
/// `unpack30.cpp` and `unpackinline.cpp`.
///
/// Implements the RAR 2.x LZSS algorithm (`Unpack20`, unpVer 20/26) and the
/// RAR 3.x algorithm (`Unpack29`, unpVer 29) with its PPMd blocks and the
/// six standard VM filters. RAR 1.5 (`unpack15.cpp`) is not ported; custom
/// RAR 3.x VM bytecode throws [UnsupportedFilterException].
library;

import 'dart:typed_data';

import 'bit_input.dart';
import 'ppmd.dart';
import 'rarvm.dart';
import 'unpack5.dart';
import 'unrar_error.dart';

// RAR 3.x alphabets (`compress.hpp`).
const int nc30 = 299;
const int dc30 = 60;
const int ldc30 = 17;
const int rc30 = 28;
const int bc30 = 20;
const int huffTableSize30 = nc30 + dc30 + ldc30 + rc30; // 404

// RAR 2.x alphabets (`compress.hpp`).
const int nc20 = 298;
const int dc20 = 48;
const int rc20 = 28;
const int bc20 = 19;
const int mc20 = 257;

/// `MAX3_INC_LZ_MATCH` (maximum match length for RAR v3, +3).
const int max3IncLzMatch = 0x104;

/// `LOW_DIST_REP_COUNT`.
const int lowDistRepCount = 16;

const int blockLz = 0;
const int blockPpm = 1;

const List<int> _lDecode = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64,
  80, 96, 112, 128, 160, 192, 224,
];

const List<int> _lBits = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
  5, 5, 5,
];

const List<int> _dDecode20 = [
  0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
  768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
  49152, 65536, 98304, 131072, 196608, 262144, 327680, 393216, 458752, 524288,
  589824, 655360, 720896, 786432, 851968, 917504, 983040,
];

const List<int> _dBits20 = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
  11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  16, 16, 16, 16, 16,
];

const List<int> _sdDecode = [0, 4, 8, 16, 32, 64, 128, 192];
const List<int> _sdBits = [2, 2, 3, 4, 5, 6, 6, 6];

/// `DBitLengthCounts` driving the one-time build of `DDecode`/`DBits` for
/// RAR 3.x distances.
const List<int> _dBitLengthCounts29 = [4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12];

/// Audio prediction variables for one channel (`AudioVariables`).
class _AudioVariables {
  int k1 = 0;
  int k2 = 0;
  int k3 = 0;
  int k4 = 0;
  int k5 = 0;
  int d1 = 0;
  int d2 = 0;
  int d3 = 0;
  int d4 = 0;
  int lastDelta = 0;
  final dif = Uint32List(11);
  int byteCount = 0;
  int lastChar = 0;
}

/// RAR 4.x (v20/v29) decompressor, ported from `Unpack::Unpack20` and
/// `Unpack::Unpack29`.
///
/// One instance keeps the sliding window and match history across solid
/// files, so a single instance must be reused while iterating an archive's
/// entries. The full packed stream of one file is held in memory.
class Rar4Unpacker {
  Rar4Unpacker();

  BitInput _inp = BitInput();
  Uint8List? _window;
  int _maxWinSize = 0;
  int _maxWinMask = 0;

  // Shared Huffman tables (LD/DD/LDD/RD/BD for v29, LD/DD/RD/BD for v20).
  final _ld = DecodeTable();
  final _dd = DecodeTable();
  final _ldd = DecodeTable();
  final _rd = DecodeTable();
  final _bd = DecodeTable();

  // RAR 2.x multimedia tables, up to 4 channels.
  final _md = List<DecodeTable>.generate(4, (_) => DecodeTable());
  final _unpOldTable20 = Uint8List(mc20 * 4);
  bool _unpAudioBlock = false;
  int _unpChannels = 1;
  int _unpCurChannel = 0;
  int _unpChannelDelta = 0;
  final _audV = List<_AudioVariables>.generate(4, (_) => _AudioVariables());

  // RAR 3.x state.
  final _unpOldTable = Uint8List(huffTableSize30);
  int _unpBlockType = blockLz;
  bool _tablesRead2 = false;
  bool _tablesRead3 = false;
  int _prevLowDist = 0;
  int _lowDistRepCount = 0;
  int _ppmEscChar = 2;
  final PpmdDecoder _ppm = PpmdDecoder();

  // RAR 3.x VM filter state (`Unpack::Filters30`, `PrgStack`,
  // `OldFilterLengths`, `LastFilter` and `VM`).
  final List<VmPreparedProgram?> _filters30 = [];
  final List<_VmStackFilter?> _prgStack = [];
  final List<int> _oldFilterLengths = [];
  int _lastFilter = 0;
  final RarVm _vm = RarVm();

  // Shared window / match state.
  final _oldDist = List<int>.filled(4, -1);
  int _oldDistPtr = 0;
  int _lastLength = 0;
  int _lastDist = 0;
  int _unpPtr = 0;
  int _prevPtr = 0;
  bool _firstWinDone = false;
  int _wrPtr = 0;
  int _readTop = 0;
  int _readBorder = 0;
  int _destUnpSize = 0;
  int _writtenFileSize = 0;
  int _packedLength = 0;
  final _output = BytesBuilder();

  /// Unpacks [packed] into a new byte buffer of [unpSize] bytes.
  ///
  /// [solid] marks a file continuing a solid stream; the window and match
  /// history of the previous file are reused. [unpVer] selects the RAR 4.x
  /// algorithm (20/26 = RAR 2.x, 29 = RAR 3.x). Returns the unpacked bytes.
  Uint8List unpack4({
    required Uint8List packed,
    required int unpSize,
    required int windowSize,
    required bool solid,
    required int unpVer,
  }) {
    _inp = BitInput.external(packed);
    _packedLength = packed.length;
    _destUnpSize = unpSize;
    _initWin(windowSize, solid);
    switch (unpVer) {
      case 20:
      case 26:
        _unpack20(solid);
        break;
      case 29:
        _unpack29(solid);
        break;
      default:
        throw UnrarException('Unsupported RAR 4.x unpVer $unpVer');
    }
    return _output.takeBytes();
  }

  /// Mirrors `Unpack::Init` for the RAR 4.x path. RAR 4 window sizes are
  /// always powers of two, so `& MaxWinMask` masking is exact.
  void _initWin(int winSize, bool solid) {
    const minAllocSize = 0x40000;
    if (winSize < minAllocSize) {
      winSize = minAllocSize;
    }
    if (!solid || _window == null) {
      _maxWinSize = winSize;
      _maxWinMask = winSize - 1;
    }
    if (_window == null || _window!.length < _maxWinSize) {
      _window = Uint8List(_maxWinSize);
    }
  }

  /// Mirrors `Unpack::UnpInitData` plus `UnpInitData20`/`UnpInitData30`.
  void _unpInitData(bool solid) {
    if (!solid) {
      _oldDist[0] = _oldDist[1] = _oldDist[2] = _oldDist[3] = -1;
      _oldDistPtr = 0;
      _lastDist = -1;
      _lastLength = 0;
      _unpPtr = _wrPtr = 0;
      _prevPtr = 0;
      _firstWinDone = false;
      // (WHY) C's `Unpack::UnpInitData` also sets `WriteBorder` here, but
      // the v20/v29 write routines (`UnpWriteBuf20`/`UnpWriteBuf30`) never
      // read it, so it is deliberately not ported. Only the RAR5 path uses
      // it (see `_writeBorder` in unpack5.dart).
      _tablesRead2 = false;
      _tablesRead3 = false;
      _unpAudioBlock = false;
      _unpChannelDelta = 0;
      _unpCurChannel = 0;
      _unpChannels = 1;
      for (final v in _audV) {
        v
          ..k1 = 0
          ..k2 = 0
          ..k3 = 0
          ..k4 = 0
          ..k5 = 0
          ..d1 = 0
          ..d2 = 0
          ..d3 = 0
          ..d4 = 0
          ..lastDelta = 0
          ..byteCount = 0
          ..lastChar = 0;
        v.dif.fillRange(0, 11, 0);
      }
      _unpOldTable20.fillRange(0, mc20 * 4, 0);
      _unpOldTable.fillRange(0, huffTableSize30, 0);
      _ppmEscChar = 2;
      _unpBlockType = blockLz;
    }
    _initFilters30(solid);
    _inp.initBitInput();
    _writtenFileSize = 0;
    _readTop = _packedLength;
    _readBorder = 0;
  }

  int _wrapUp(int pos) => pos >= _maxWinSize ? pos - _maxWinSize : pos;

  /// Mirrors `Unpack::UnpReadBuf`/`UnpReadBuf30` in the external-buffer mode:
  /// the whole packed stream is already in memory, so there is nothing to
  /// read or relocate, only the EOF and border accounting is kept.
  bool _unpReadBuf() {
    if (_inp.inAddr > _readTop) {
      return false;
    }
    _readBorder = _readTop - 30;
    return true;
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

  /// Mirrors `Unpack::UnpWriteArea` for a single contiguous window.
  void _unpWriteArea(int startPtr, int endPtr) {
    final window = _window!;
    if (endPtr < startPtr) {
      _unpWriteData(
          Uint8List.sublistView(window, startPtr, _maxWinSize),
          _maxWinSize - startPtr);
      _unpWriteData(Uint8List.sublistView(window, 0, endPtr), endPtr);
    } else {
      _unpWriteData(
          Uint8List.sublistView(window, startPtr, endPtr), endPtr - startPtr);
    }
  }

  /// Mirrors `Unpack::UnpWriteBuf20`. Writes the window segment between
  /// [WrPtr] and [UnpPtr], wrapping around the window end.
  void _unpWriteBuf20() {
    final window = _window!;
    if (_unpPtr < _wrPtr) {
      _unpWriteData(Uint8List.sublistView(window, _wrPtr, _maxWinSize),
          _maxWinSize - _wrPtr);
      _unpWriteData(Uint8List.sublistView(window, 0, _unpPtr), _unpPtr);
    } else {
      _unpWriteData(
          Uint8List.sublistView(window, _wrPtr, _unpPtr), _unpPtr - _wrPtr);
    }
    _wrPtr = _unpPtr;
  }

  /// Mirrors `Unpack::InitFilters30`.
  void _initFilters30(bool solid) {
    if (!solid) {
      _oldFilterLengths.clear();
      _lastFilter = 0;
      _filters30.clear();
    }
    _prgStack.clear();
  }

  /// Mirrors `Unpack::UnpWriteBuf30` with the pending VM filters applied.
  void _unpWriteBuf30() {
    var writtenBorder = _wrPtr;
    var writeSize = (_unpPtr - writtenBorder) & _maxWinMask;
    for (var i = 0; i < _prgStack.length; i++) {
      final flt = _prgStack[i];
      if (flt == null) {
        continue;
      }
      if (flt.nextWindow) {
        flt.nextWindow = false;
        continue;
      }
      final blockStart = flt.blockStart;
      final blockLength = flt.blockLength;
      if (((blockStart - writtenBorder) & _maxWinMask) >= writeSize) {
        continue;
      }
      if (writtenBorder != blockStart) {
        _unpWriteArea(writtenBorder, blockStart);
        writtenBorder = blockStart;
        writeSize = (_unpPtr - writtenBorder) & _maxWinMask;
      }
      if (blockLength > writeSize) {
        // Current filter intersects the window write border, so we adjust
        // the window border to process this filter next time, not now.
        for (var j = i; j < _prgStack.length; j++) {
          final f = _prgStack[j];
          if (f != null && f.nextWindow) {
            f.nextWindow = false;
          }
        }
        _wrPtr = writtenBorder;
        return;
      }
      final blockEnd = (blockStart + blockLength) & _maxWinMask;
      if (blockStart < blockEnd || blockEnd == 0) {
        _vm.setMemory(0, _window!, blockStart, blockLength);
      } else {
        final firstPartLength = _maxWinSize - blockStart;
        _vm.setMemory(0, _window!, blockStart, firstPartLength);
        _vm.setMemory(firstPartLength, _window!, 0, blockEnd);
      }

      final prg = flt.prg;
      _executeCode(prg);
      var filteredData = prg.filteredData;
      var filteredDataSize = prg.filteredDataSize;

      _prgStack[i] = null;
      while (i + 1 < _prgStack.length) {
        final nextFilter = _prgStack[i + 1];
        // It is required to check NextWindow here.
        if (nextFilter == null ||
            nextFilter.blockStart != blockStart ||
            nextFilter.blockLength != filteredDataSize ||
            nextFilter.nextWindow) {
          break;
        }

        // Apply several filters to the same data block.
        _vm.setMemory(0, filteredData!, 0, filteredDataSize);

        final nextPrg = nextFilter.prg;
        _executeCode(nextPrg);
        filteredData = nextPrg.filteredData;
        filteredDataSize = nextPrg.filteredDataSize;
        i++;
        _prgStack[i] = null;
      }
      _unpWriteData(filteredData!, filteredDataSize);
      writtenBorder = blockEnd;
      writeSize = (_unpPtr - writtenBorder) & _maxWinMask;
    }

    _unpWriteArea(writtenBorder, _unpPtr);
    _wrPtr = _unpPtr;
  }

  /// Mirrors `Unpack::InsertOldDist`.
  void _insertOldDist(int distance) {
    _oldDist[3] = _oldDist[2];
    _oldDist[2] = _oldDist[1];
    _oldDist[1] = _oldDist[0];
    _oldDist[0] = distance;
  }

  /// Mirrors `Unpack::CopyString`. A byte-wise forward copy matches the C
  /// `UNPACK_COPY8` behavior for overlapping and non-overlapping strings.
  void _copyString(int length, int distance) {
    final window = _window!;
    var srcPtr = _unpPtr - distance;

    if (distance > _unpPtr) {
      // Same as WrapDown(SrcPtr), needed because of UnpPtr-Distance above.
      srcPtr += _maxWinSize;

      // Zero-fill the match area for distances beyond the window or before
      // the first window has been filled, like the C code, so corrupt data
      // does not depend on previously extracted files.
      if (distance > _maxWinSize || !_firstWinDone) {
        while (length-- > 0) {
          window[_unpPtr] = 0;
          _unpPtr = _wrapUp(_unpPtr + 1);
        }
        return;
      }
    }

    if (srcPtr < _maxWinSize - maxIncLzMatch &&
        _unpPtr < _maxWinSize - maxIncLzMatch) {
      // Fast path: nowhere near the window borders, no wrap checks needed.
      var src = srcPtr;
      var dest = _unpPtr;
      _unpPtr += length;
      while (length-- > 0) {
        window[dest++] = window[src++];
      }
    } else {
      // Slow path with all possible precautions.
      while (length-- > 0) {
        window[_unpPtr] = window[_wrapUp(srcPtr++)];
        _unpPtr = _wrapUp(_unpPtr + 1);
      }
    }
  }

  /// Mirrors `Unpack::CopyString20`.
  void _copyString20(int length, int distance) {
    _lastDist = distance;
    _oldDist[_oldDistPtr++] = distance;
    _oldDistPtr = _oldDistPtr & 3;
    _lastLength = length;
    _destUnpSize -= length;
    _copyString(length, distance);
  }

  /// Mirrors `Unpack::SafePPMDecodeChar`.
  int _safePpmDecodeChar() {
    final ch = _ppm.decodeChar();
    if (ch == -1) {
      // Corrupt PPM data found; reset and fall back to LZ mode.
      _ppm.cleanUp();
      _unpBlockType = blockLz;
    }
    return ch;
  }

  /// Mirrors `Unpack::Unpack20` (RAR 2.x compression).
  void _unpack20(bool solid) {
    _unpInitData(solid);
    if (!_unpReadBuf()) {
      return;
    }
    if ((!solid || !_tablesRead2) && !_readTables20()) {
      return;
    }
    _destUnpSize--;

    while (_destUnpSize >= 0) {
      _unpPtr &= _maxWinMask;

      _firstWinDone |= (_prevPtr > _unpPtr);
      _prevPtr = _unpPtr;

      if (_inp.inAddr > _readTop - 30) {
        if (!_unpReadBuf()) {
          break;
        }
      }
      if (((_wrPtr - _unpPtr) & _maxWinMask) < 270 && _wrPtr != _unpPtr) {
        _unpWriteBuf20();
      }
      if (_unpAudioBlock) {
        final audioNumber = decodeNumber(_inp, _md[_unpCurChannel]);

        if (audioNumber == 256) {
          if (!_readTables20()) {
            break;
          }
          continue;
        }
        _window![_unpPtr++] = _decodeAudio(audioNumber);
        if (++_unpCurChannel == _unpChannels) {
          _unpCurChannel = 0;
        }
        --_destUnpSize;
        continue;
      }

      final number = decodeNumber(_inp, _ld);
      if (number < 256) {
        _window![_unpPtr++] = number;
        --_destUnpSize;
        continue;
      }
      if (number > 269) {
        var n = number - 270;
        var length = _lDecode[n] + 3;
        var bits = _lBits[n];
        if (bits > 0) {
          length += _inp.getbits() >> (16 - bits);
          _inp.addbits(bits);
        }

        final distNumber = decodeNumber(_inp, _dd);
        var distance = _dDecode20[distNumber] + 1;
        bits = _dBits20[distNumber];
        if (bits > 0) {
          distance += _inp.getbits() >> (16 - bits);
          _inp.addbits(bits);
        }

        if (distance >= 0x2000) {
          length++;
          if (distance >= 0x40000) {
            length++;
          }
        }

        _copyString20(length, distance);
        continue;
      }
      if (number == 269) {
        if (!_readTables20()) {
          break;
        }
        continue;
      }
      if (number == 256) {
        _copyString20(_lastLength, _lastDist);
        continue;
      }
      if (number < 261) {
        final distance = _oldDist[(_oldDistPtr - (number - 256)) & 3];
        final lengthNumber = decodeNumber(_inp, _rd);
        var length = _lDecode[lengthNumber] + 2;
        final bits = _lBits[lengthNumber];
        if (bits > 0) {
          length += _inp.getbits() >> (16 - bits);
          _inp.addbits(bits);
        }
        if (distance >= 0x101) {
          length++;
          if (distance >= 0x2000) {
            length++;
            if (distance >= 0x40000) {
              length++;
            }
          }
        }
        _copyString20(length, distance);
        continue;
      }
      // number is in 261..269.
      var n = number - 261;
      var distance = _sdDecode[n] + 1;
      final bits = _sdBits[n];
      if (bits > 0) {
        distance += _inp.getbits() >> (16 - bits);
        _inp.addbits(bits);
      }
      _copyString20(2, distance);
    }
    _readLastTables();
    _unpWriteBuf20();
  }

  /// Mirrors `Unpack::Unpack29` (RAR 3.x compression).
  void _unpack29(bool solid) {
    _initDDecode29();

    _unpInitData(solid);
    if (!_unpReadBuf()) {
      return;
    }
    if ((!solid || !_tablesRead3) && !_readTables30()) {
      return;
    }

    while (true) {
      _unpPtr &= _maxWinMask;

      _firstWinDone |= (_prevPtr > _unpPtr);
      _prevPtr = _unpPtr;

      if (_inp.inAddr > _readBorder) {
        if (!_unpReadBuf()) {
          break;
        }
      }
      if (((_wrPtr - _unpPtr) & _maxWinMask) <= max3IncLzMatch &&
          _wrPtr != _unpPtr) {
        _unpWriteBuf30();
        if (_writtenFileSize > _destUnpSize) {
          return;
        }
      }
      if (_unpBlockType == blockPpm) {
        // Here speed is critical, so we do not use SafePPMDecodeChar.
        var ch = _ppm.decodeChar();
        if (ch == -1) {
          _ppm.cleanUp();
          _unpBlockType = blockLz;
          break;
        }
        if (ch == _ppmEscChar) {
          final nextCh = _safePpmDecodeChar();
          if (nextCh == 0) {
            // End of PPM encoding.
            if (!_readTables30()) {
              break;
            }
            continue;
          }
          if (nextCh == -1) {
            break;
          }
          if (nextCh == 2) {
            // End of file in PPM mode.
            break;
          }
          if (nextCh == 3) {
            // Read VM code (filters are not ported, fail safely).
            if (!_readVmCodePpm()) {
              break;
            }
            continue;
          }
          if (nextCh == 4) {
            // LZ inside of PPM.
            var distance = 0;
            var length = 0;
            var failed = false;
            for (var i = 0; i < 4 && !failed; i++) {
              final ch2 = _safePpmDecodeChar();
              if (ch2 == -1) {
                failed = true;
              } else if (i == 3) {
                length = ch2 & 0xff;
              } else {
                distance = ((distance << 8) + (ch2 & 0xff)) & 0xFFFFFFFF;
              }
            }
            if (failed) {
              break;
            }
            _copyString(length + 32, distance + 2);
            continue;
          }
          if (nextCh == 5) {
            // One byte distance match (RLE) inside of PPM.
            final length = _safePpmDecodeChar();
            if (length == -1) {
              break;
            }
            _copyString(length + 4, 1);
            continue;
          }
          // nextCh must be 1: the current byte equals the escape byte.
        }
        _window![_unpPtr++] = ch;
        continue;
      }

      final number = decodeNumber(_inp, _ld);
      if (number < 256) {
        _window![_unpPtr++] = number;
        continue;
      }
      if (number >= 271) {
        var n = number - 271;
        var length = _lDecode[n] + 3;
        var bits = _lBits[n];
        if (bits > 0) {
          length += _inp.getbits() >> (16 - bits);
          _inp.addbits(bits);
        }

        final distNumber = decodeNumber(_inp, _dd);
        var distance = _dDecode29[distNumber] + 1;
        bits = _dBits29[distNumber];
        if (bits > 0) {
          if (distNumber > 9) {
            if (bits > 4) {
              distance += ((_inp.getbits() >> (20 - bits)) << 4);
              _inp.addbits(bits - 4);
            }
            if (_lowDistRepCount > 0) {
              _lowDistRepCount--;
              distance += _prevLowDist;
            } else {
              final lowDist = decodeNumber(_inp, _ldd);
              if (lowDist == 16) {
                _lowDistRepCount = lowDistRepCount - 1;
                distance += _prevLowDist;
              } else {
                distance += lowDist;
                _prevLowDist = lowDist;
              }
            }
          } else {
            distance += _inp.getbits() >> (16 - bits);
            _inp.addbits(bits);
          }
        }

        if (distance >= 0x2000) {
          length++;
          if (distance >= 0x40000) {
            length++;
          }
        }

        _insertOldDist(distance);
        _lastLength = length;
        _copyString(length, distance);
        continue;
      }
      if (number == 256) {
        if (!_readEndOfBlock()) {
          break;
        }
        continue;
      }
      if (number == 257) {
        if (!_readVmCode()) {
          break;
        }
        continue;
      }
      if (number == 258) {
        if (_lastLength != 0) {
          _copyString(_lastLength, _oldDist[0]);
        }
        continue;
      }
      if (number < 263) {
        final distNum = number - 259;
        var distance = _oldDist[distNum];
        for (var i = distNum; i > 0; i--) {
          _oldDist[i] = _oldDist[i - 1];
        }
        _oldDist[0] = distance;

        final lengthNumber = decodeNumber(_inp, _rd);
        var length = _lDecode[lengthNumber] + 2;
        final bits = _lBits[lengthNumber];
        if (bits > 0) {
          length += _inp.getbits() >> (16 - bits);
          _inp.addbits(bits);
        }
        _lastLength = length;
        _copyString(length, distance);
        continue;
      }
      // number is in 263..271.
      var n = number - 263;
      var distance = _sdDecode[n] + 1;
      final bits = _sdBits[n];
      if (bits > 0) {
        distance += _inp.getbits() >> (16 - bits);
        _inp.addbits(bits);
      }
      _insertOldDist(distance);
      _lastLength = 2;
      _copyString(2, distance);
    }
    _unpWriteBuf30();
  }

  /// Mirrors `Unpack::ReadEndOfBlock`.
  bool _readEndOfBlock() {
    final bitField = _inp.getbits();
    var newTable = false;
    var newFile = false;

    // "1"  - no new file, new table just here.
    // "00" - new file,    no new table.
    // "01" - new file,    new table (in beginning of next file).
    if ((bitField & 0x8000) != 0) {
      newTable = true;
      _inp.addbits(1);
    } else {
      newFile = true;
      newTable = (bitField & 0x4000) != 0;
      _inp.addbits(2);
    }
    _tablesRead3 = !newTable;

    if (newFile) {
      return false;
    }
    return _readTables30();
  }

  /// Mirrors `Unpack::ReadTables30`.
  bool _readTables30() {
    final bitLength = Uint8List(bc30);
    final table = Uint8List(huffTableSize30);
    if (_inp.inAddr > _readTop - 25) {
      if (!_unpReadBuf()) {
        return false;
      }
    }
    _inp.addbits((8 - _inp.inBit) & 7);
    final bitField = _inp.getbits();
    if ((bitField & 0x8000) != 0) {
      _unpBlockType = blockPpm;
      final ok = _ppm.decodeInit(_inp, _ppmEscChar);
      _ppmEscChar = _ppm.escChar;
      return ok;
    }
    _unpBlockType = blockLz;

    _prevLowDist = 0;
    _lowDistRepCount = 0;

    if ((bitField & 0x4000) == 0) {
      _unpOldTable.fillRange(0, huffTableSize30, 0);
    }
    _inp.addbits(2);

    for (var i = 0; i < bc30; i++) {
      var length = (_inp.getbits() >> 12) & 0xff;
      _inp.addbits(4);
      if (length == 15) {
        final zeroCount0 = (_inp.getbits() >> 12) & 0xff;
        _inp.addbits(4);
        if (zeroCount0 == 0) {
          bitLength[i] = 15;
        } else {
          var zeroCount = zeroCount0 + 2;
          while (zeroCount-- > 0 && i < bitLength.length) {
            bitLength[i++] = 0;
          }
          i--;
        }
      } else {
        bitLength[i] = length;
      }
    }
    makeDecodeTables(bitLength, _bd, bc30);

    for (var i = 0; i < huffTableSize30;) {
      if (_inp.inAddr > _readTop - 5) {
        if (!_unpReadBuf()) {
          return false;
        }
      }
      final number = decodeNumber(_inp, _bd);
      if (number < 16) {
        table[i] = (number + _unpOldTable[i]) & 0xf;
        i++;
      } else if (number < 18) {
        var n = 0;
        if (number == 16) {
          n = (_inp.getbits() >> 13) + 3;
          _inp.addbits(3);
        } else {
          n = (_inp.getbits() >> 9) + 11;
          _inp.addbits(7);
        }
        if (i == 0) {
          // "Repeat previous" code cannot be the first position.
          return false;
        }
        while (n-- > 0 && i < huffTableSize30) {
          table[i] = table[i - 1];
          i++;
        }
      } else {
        var n = 0;
        if (number == 18) {
          n = (_inp.getbits() >> 13) + 3;
          _inp.addbits(3);
        } else {
          n = (_inp.getbits() >> 9) + 11;
          _inp.addbits(7);
        }
        while (n-- > 0 && i < huffTableSize30) {
          table[i++] = 0;
        }
      }
    }
    _tablesRead3 = true;
    if (_inp.inAddr > _readTop) {
      return false;
    }
    makeDecodeTables(table.sublist(0, nc30), _ld, nc30);
    makeDecodeTables(table.sublist(nc30, nc30 + dc30), _dd, dc30);
    makeDecodeTables(table.sublist(nc30 + dc30, nc30 + dc30 + ldc30), _ldd, ldc30);
    makeDecodeTables(table.sublist(nc30 + dc30 + ldc30), _rd, rc30);
    _unpOldTable.setRange(0, huffTableSize30, table);
    return true;
  }

  /// Mirrors `Unpack::ReadTables20`.
  bool _readTables20() {
    final bitLength = Uint8List(bc20);
    final table = Uint8List(mc20 * 4);
    if (_inp.inAddr > _readTop - 25) {
      if (!_unpReadBuf()) {
        return false;
      }
    }
    final bitField = _inp.getbits();
    _unpAudioBlock = (bitField & 0x8000) != 0;

    if ((bitField & 0x4000) == 0) {
      _unpOldTable20.fillRange(0, mc20 * 4, 0);
    }
    _inp.addbits(2);

    var tableSize = 0;
    if (_unpAudioBlock) {
      _unpChannels = ((bitField >> 12) & 3) + 1;
      if (_unpCurChannel >= _unpChannels) {
        _unpCurChannel = 0;
      }
      _inp.addbits(2);
      tableSize = mc20 * _unpChannels;
    } else {
      tableSize = nc20 + dc20 + rc20;
    }

    for (var i = 0; i < bc20; i++) {
      bitLength[i] = (_inp.getbits() >> 12) & 0xff;
      _inp.addbits(4);
    }
    makeDecodeTables(bitLength, _bd, bc20);

    for (var i = 0; i < tableSize;) {
      if (_inp.inAddr > _readTop - 5) {
        if (!_unpReadBuf()) {
          return false;
        }
      }
      final number = decodeNumber(_inp, _bd);
      if (number < 16) {
        table[i] = (number + _unpOldTable20[i]) & 0xf;
        i++;
      } else if (number == 16) {
        var n = (_inp.getbits() >> 14) + 3;
        _inp.addbits(2);
        if (i == 0) {
          return false;
        }
        while (n-- > 0 && i < tableSize) {
          table[i] = table[i - 1];
          i++;
        }
      } else {
        var n = 0;
        if (number == 17) {
          n = (_inp.getbits() >> 13) + 3;
          _inp.addbits(3);
        } else {
          n = (_inp.getbits() >> 9) + 11;
          _inp.addbits(7);
        }
        while (n-- > 0 && i < tableSize) {
          table[i++] = 0;
        }
      }
    }
    _tablesRead2 = true;
    if (_inp.inAddr > _readTop) {
      return true;
    }
    if (_unpAudioBlock) {
      for (var i = 0; i < _unpChannels; i++) {
        makeDecodeTables(
            table.sublist(i * mc20, (i + 1) * mc20), _md[i], mc20);
      }
    } else {
      makeDecodeTables(table.sublist(0, nc20), _ld, nc20);
      makeDecodeTables(table.sublist(nc20, nc20 + dc20), _dd, dc20);
      makeDecodeTables(table.sublist(nc20 + dc20), _rd, rc20);
    }
    _unpOldTable20.setRange(0, tableSize, table);
    return true;
  }

  /// Mirrors `Unpack::ReadLastTables`.
  void _readLastTables() {
    if (_readTop >= _inp.inAddr + 5) {
      if (_unpAudioBlock) {
        if (decodeNumber(_inp, _md[_unpCurChannel]) == 256) {
          _readTables20();
        }
      } else if (decodeNumber(_inp, _ld) == 269) {
        _readTables20();
      }
    }
  }

  /// Mirrors `Unpack::DecodeAudio`.
  int _decodeAudio(int delta) {
    final v = _audV[_unpCurChannel];
    v.byteCount++;
    v.d4 = v.d3;
    v.d3 = v.d2;
    v.d2 = v.lastDelta - v.d1;
    v.d1 = v.lastDelta;
    final pch = (8 * v.lastChar +
            v.k1 * v.d1 +
            v.k2 * v.d2 +
            v.k3 * v.d3 +
            v.k4 * v.d4 +
            v.k5 * _unpChannelDelta) >>
        3 & 0xff;

    final ch = (pch - delta) & 0xff;

    // D is the delta scaled by 8; the C code computes it via unsigned shifts
    // to avoid UB, with signed-magnitude semantics, so the plain signed
    // arithmetic below matches the resulting behavior.
    final sd = delta < 128 ? delta : delta - 256; // signed byte.
    final d = sd << 3;
    v.dif[0] += d.abs();
    v.dif[1] += (d - v.d1).abs();
    v.dif[2] += (d + v.d1).abs();
    v.dif[3] += (d - v.d2).abs();
    v.dif[4] += (d + v.d2).abs();
    v.dif[5] += (d - v.d3).abs();
    v.dif[6] += (d + v.d3).abs();
    v.dif[7] += (d - v.d4).abs();
    v.dif[8] += (d + v.d4).abs();
    v.dif[9] += (d - _unpChannelDelta).abs();
    v.dif[10] += (d + _unpChannelDelta).abs();

    final lastDelta = (ch - v.lastChar).toSigned(8);
    _unpChannelDelta = lastDelta;
    v.lastDelta = lastDelta;
    v.lastChar = ch;

    if ((v.byteCount & 0x1f) == 0) {
      var minDif = v.dif[0];
      var numMinDif = 0;
      v.dif[0] = 0;
      for (var i = 1; i < 11; i++) {
        if (v.dif[i] < minDif) {
          minDif = v.dif[i];
          numMinDif = i;
        }
        v.dif[i] = 0;
      }
      switch (numMinDif) {
        case 1:
          if (v.k1 >= -16) {
            v.k1--;
          }
          break;
        case 2:
          if (v.k1 < 16) {
            v.k1++;
          }
          break;
        case 3:
          if (v.k2 >= -16) {
            v.k2--;
          }
          break;
        case 4:
          if (v.k2 < 16) {
            v.k2++;
          }
          break;
        case 5:
          if (v.k3 >= -16) {
            v.k3--;
          }
          break;
        case 6:
          if (v.k3 < 16) {
            v.k3++;
          }
          break;
        case 7:
          if (v.k4 >= -16) {
            v.k4--;
          }
          break;
        case 8:
          if (v.k4 < 16) {
            v.k4++;
          }
          break;
        case 9:
          if (v.k5 >= -16) {
            v.k5--;
          }
          break;
        case 10:
          if (v.k5 < 16) {
            v.k5++;
          }
          break;
      }
    }
    return ch;
  }

  /// Mirrors `Unpack::ReadVMCode` (LZ mode). Reads the VM code marker,
  /// then decodes and registers the filter described by it.
  bool _readVmCode() {
    final inp = _inp;
    final firstByte = inp.getbits() >> 8;
    inp.addbits(8);
    var length = (firstByte & 7) + 1;
    if (length == 7) {
      length = (inp.getbits() >> 8) + 7;
      inp.addbits(8);
    } else if (length == 8) {
      length = inp.getbits();
      inp.addbits(16);
    }
    if (length == 0) {
      return false;
    }
    final code = Uint8List(length);
    for (var i = 0; i < length; i++) {
      // Try to read the new buffer if only one byte is left. In the
      // external-buffer mode the whole stream is in memory, so this only
      // keeps the EOF accounting.
      if (inp.inAddr >= _readTop - 1 && !_unpReadBuf() && i < length - 1) {
        return false;
      }
      code[i] = inp.getbits() >> 8;
      inp.addbits(8);
    }
    return _addVmCode(firstByte, code);
  }

  /// Mirrors `Unpack::ReadVMCodePPM` (PPM mode).
  bool _readVmCodePpm() {
    var firstByte = _safePpmDecodeChar();
    if (firstByte == -1) {
      return false;
    }
    var length = (firstByte & 7) + 1;
    if (length == 7) {
      final b1 = _safePpmDecodeChar();
      if (b1 == -1) {
        return false;
      }
      length = b1 + 7;
    } else if (length == 8) {
      final b1 = _safePpmDecodeChar();
      if (b1 == -1) {
        return false;
      }
      final b2 = _safePpmDecodeChar();
      if (b2 == -1) {
        return false;
      }
      length = b1 * 256 + b2;
    }
    if (length == 0) {
      return false;
    }
    final code = Uint8List(length);
    for (var i = 0; i < length; i++) {
      final ch = _safePpmDecodeChar();
      if (ch == -1) {
        return false;
      }
      code[i] = ch;
    }
    return _addVmCode(firstByte, code);
  }

  /// Mirrors `Unpack::AddVMCode`. Reads the filter placement parameters,
  /// records the filter on the pending stack and, for a new filter, decodes
  /// and prepares its VM bytecode.
  ///
  /// Custom VM programs that do not match any of the six standard filters
  /// throw [UnsupportedFilterException]: the bytecode interpreter is not
  /// ported, and the C library would silently write nothing for them.
  bool _addVmCode(int firstByte, Uint8List code) {
    final vmCodeInp = BitInput.external(code);
    _vm.init();

    var filtPos = _lastFilter;
    if ((firstByte & 0x80) != 0) {
      filtPos = RarVm.readData(vmCodeInp);
      if (filtPos == 0) {
        _initFilters30(false);
      } else {
        filtPos--;
      }
    }

    if (filtPos > _filters30.length || filtPos > _oldFilterLengths.length) {
      return false;
    }
    _lastFilter = filtPos;
    final newFilter = filtPos == _filters30.length;

    final stackFilter = _VmStackFilter();

    late final VmPreparedProgram filter;
    if (newFilter) {
      if (filtPos > max3UnpackFilters) {
        return false;
      }
      stackFilter.parentFilter = _filters30.length;
      filter = VmPreparedProgram();
      _filters30.add(filter);
      _oldFilterLengths.add(0);
    } else {
      filter = _filters30[filtPos]!;
      stackFilter.parentFilter = filtPos;
    }

    // Compact the null entries left by already-processed filters.
    var emptyCount = 0;
    for (var i = 0; i < _prgStack.length; i++) {
      _prgStack[i - emptyCount] = _prgStack[i];
      if (_prgStack[i] == null) {
        emptyCount++;
      }
      if (emptyCount > 0) {
        _prgStack[i] = null;
      }
    }
    if (emptyCount == 0) {
      if (_prgStack.length > max3UnpackFilters) {
        return false;
      }
      _prgStack.add(null);
      emptyCount = 1;
    }
    final stackPos = _prgStack.length - emptyCount;
    _prgStack[stackPos] = stackFilter;

    var blockStart = RarVm.readData(vmCodeInp);
    if ((firstByte & 0x40) != 0) {
      blockStart += 258;
    }
    stackFilter.blockStart = (blockStart + _unpPtr) & _maxWinMask;
    if ((firstByte & 0x20) != 0) {
      stackFilter.blockLength = RarVm.readData(vmCodeInp);
      _oldFilterLengths[filtPos] = stackFilter.blockLength;
    } else {
      stackFilter.blockLength = filtPos < _oldFilterLengths.length
          ? _oldFilterLengths[filtPos]
          : 0;
    }

    stackFilter.nextWindow =
        _wrPtr != _unpPtr && ((_wrPtr - _unpPtr) & _maxWinMask) <= blockStart;

    stackFilter.prg.initR.fillRange(0, 7, 0);
    stackFilter.prg.initR[4] = stackFilter.blockLength;

    if ((firstByte & 0x10) != 0) {
      final initMask = vmCodeInp.getbits() >> 9;
      vmCodeInp.addbits(7);
      for (var i = 0; i < 7; i++) {
        if ((initMask & (1 << i)) != 0) {
          stackFilter.prg.initR[i] = RarVm.readData(vmCodeInp);
        }
      }
    }

    if (newFilter) {
      final vmCodeSize = RarVm.readData(vmCodeInp);
      if (vmCodeSize >= 0x10000 ||
          vmCodeSize == 0 ||
          vmCodeInp.inAddr + vmCodeSize > code.length) {
        return false;
      }
      final vmCode = Uint8List(vmCodeSize);
      for (var i = 0; i < vmCodeSize; i++) {
        if (vmCodeInp.overflow(3)) {
          return false;
        }
        vmCode[i] = vmCodeInp.getbits() >> 8;
        vmCodeInp.addbits(8);
      }
      _vm.prepare(vmCode, filter);
      if (filter.type == VmStandardFilter.none) {
        throw const UnsupportedFilterException(
            'RAR3 VM filter bytecode matches none of the six standard '
            'filters (E8/E8E9/ITANIUM/DELTA/RGB/AUDIO); the VM interpreter '
            'is not ported.');
      }
    }
    stackFilter.prg.type = filter.type;

    return true;
  }

  /// Mirrors `Unpack::ExecuteCode`.
  void _executeCode(VmPreparedProgram prg) {
    prg.initR[6] = _writtenFileSize & 0xFFFFFFFF;
    _vm.execute(prg);
  }
}

/// Mirrors `UnpackFilter30` (the per-instance filter state kept on the
/// pending filter stack).
class _VmStackFilter {
  int parentFilter = 0;
  int blockStart = 0;
  int blockLength = 0;
  bool nextWindow = false;
  final VmPreparedProgram prg = VmPreparedProgram();
}

/// One-time build of the RAR 3.x distance decode tables (`DDecode`/`DBits`),
/// mirroring the `DDecode[1]==0` guard in `Unpack29`.
void _initDDecode29() {
  if (_dDecode29[1] == 0) {
    var dist = 0;
    var bitLength = 0;
    var slot = 0;
    for (var i = 0; i < _dBitLengthCounts29.length; i++, bitLength++) {
      for (var j = 0; j < _dBitLengthCounts29[i]; j++, slot++, dist += (1 << bitLength)) {
        _dDecode29[slot] = dist;
        _dBits29[slot] = bitLength;
      }
    }
  }
}

final List<int> _dDecode29 = List<int>.filled(dc30, 0);
final List<int> _dBits29 = List<int>.filled(dc30, 0);
