/// RAR 1.5 decompressor, ported from `unpack15.cpp` / `unpack.cpp`.
///
/// Entry point: [Rar15Unpacker.unpack15].
///
/// The algorithm is a flag-steered mix of three coding modes:
///   • **HuffDecode** – adaptive-Huffman literal bytes
///   • **ShortLZ**    – short LZ back-references
///   • **LongLZ**     – long LZ back-references
///
/// Each mode uses self-organising frequency tables (`ChSet*`/`NToPl*`) that
/// move recently seen symbols towards lower indices (move-to-front variant).
/// `CorrHuff` rebuilds the priority ordering when a counter overflows.
///
/// The port is a direct translation of the C source; all variable names
/// and structure mirror the original to make cross-referencing easy.
library;

import 'dart:typed_data';

import 'bit_input.dart';

// Huffman decode tables (static constants from unpack15.cpp).

const int _startL1 = 2;
const List<int> _decL1 = [
  0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000,
  0xf200, 0xf200, 0xffff,
];
const List<int> _posL1 = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];

const int _startL2 = 3;
const List<int> _decL2 = [
  0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200,
  0xf240, 0xffff,
];
const List<int> _posL2 = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];

const int _startHf0 = 4;
const List<int> _decHf0 = [
  0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff,
];
const List<int> _posHf0 = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];

const int _startHf1 = 5;
const List<int> _decHf1 = [
  0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff,
];
const List<int> _posHf1 = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];

const int _startHf2 = 5;
const List<int> _decHf2 = [
  0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff,
];
const List<int> _posHf2 = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];

const int _startHf3 = 6;
const List<int> _decHf3 = [
  0x800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff,
];
const List<int> _posHf3 = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];

const int _startHf4 = 8;
const List<int> _decHf4 = [
  0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
];
const List<int> _posHf4 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const int _maxWinSize = 0x10000;
const int _maxWinMask = 0xffff;

/// RAR 1.5 (unpVer 13 / 10) decompressor.
class Rar15Unpacker {
  // Window buffer (64 KB).
  final Uint16List _chSet = Uint16List(256);
  final Uint16List _chSetA = Uint16List(256);
  final Uint16List _chSetB = Uint16List(256);
  final Uint16List _chSetC = Uint16List(256);
  final Uint8List _nToPl = Uint8List(256);
  final Uint8List _nToPlB = Uint8List(256);
  final Uint8List _nToPlC = Uint8List(256);
  final Uint8List _window = Uint8List(_maxWinSize);

  // Decompressor state.
  int _unpPtr = 0;
  int _wrPtr = 0;
  bool _firstWinDone = false;
  int _prevPtr = 0;

  // LZ state.
  final List<int> _oldDist = [0, 0, 0, 0];
  int _oldDistPtr = 0;
  int _lastDist = 0;
  int _lastLength = 0;

  // Statistical state.
  int _avrPlc = 0x3500;
  int _avrPlcB = 0;
  int _avrLn1 = 0;
  int _avrLn2 = 0;
  int _avrLn3 = 0;
  int _maxDist3 = 0x2001;
  int _nhfb = 0x80;
  int _nlzb = 0x80;
  int _numHuf = 0;
  int _buf60 = 0;
  int _stMode = 0;
  int _flagsCnt = 0;
  int _flagBuf = 0;
  int _lCount = 0;

  // Output accumulator.
  final List<int> _out = [];
  int _destUnpSize = 0;

  // Bit reader.
  late BitInput _inp;

  /// Decompresses [packed] and returns the first [unpSize] unpacked bytes.
  ///
  /// [solid] carries the window state forward when `true` (not reset).
  Uint8List unpack15(
      {required Uint8List packed, required int unpSize, bool solid = false}) {
    _inp = BitInput.external(packed);
    _destUnpSize = unpSize;
    _out.clear();

    _unpInitData15(solid);
    if (!solid) {
      _initHuff();
      _unpPtr = 0;
    } else {
      _unpPtr = _wrPtr;
    }

    --_destUnpSize;
    if (_destUnpSize >= 0) {
      _getFlagsBuf();
      _flagsCnt = 8;
    }

    while (_destUnpSize >= 0) {
      _unpPtr &= _maxWinMask;

      if (_prevPtr > _unpPtr) _firstWinDone = true;
      _prevPtr = _unpPtr;

      // Flush window to output when write pointer is about to lap unpack pointer.
      if (((_wrPtr - _unpPtr) & _maxWinMask) < 270 && _wrPtr != _unpPtr) {
        _writeBuf20();
      }

      if (_stMode != 0) {
        _huffDecode();
        continue;
      }

      if (--_flagsCnt < 0) {
        _getFlagsBuf();
        _flagsCnt = 7;
      }

      if ((_flagBuf & 0x80) != 0) {
        _flagBuf = (_flagBuf << 1) & 0xff;
        if (_nlzb > _nhfb) {
          _longLz();
        } else {
          _huffDecode();
        }
      } else {
        _flagBuf = (_flagBuf << 1) & 0xff;
        if (--_flagsCnt < 0) {
          _getFlagsBuf();
          _flagsCnt = 7;
        }
        if ((_flagBuf & 0x80) != 0) {
          _flagBuf = (_flagBuf << 1) & 0xff;
          if (_nlzb > _nhfb) {
            _huffDecode();
          } else {
            _longLz();
          }
        } else {
          _flagBuf = (_flagBuf << 1) & 0xff;
          _shortLz();
        }
      }
    }
    _writeBuf();

    return Uint8List.fromList(
        _out.length > unpSize ? _out.sublist(0, unpSize) : _out);
  }

  // ---------------------------------------------------------------------------
  // Bit helpers — mirror fgetbits() / faddbits().
  // ---------------------------------------------------------------------------

  int _fgetbits() => _inp.getbits();
  void _faddbits(int n) => _inp.addbits(n);

  // ---------------------------------------------------------------------------
  // Buffer-flush — write window[WrPtr..UnpPtr] to _out.
  // ---------------------------------------------------------------------------

  void _writeBuf() {
    var wp = _wrPtr;
    final up = _unpPtr & _maxWinMask;
    while (wp != up && _out.length < _destUnpSize + 1 + _out.length) {
      _out.add(_window[wp]);
      wp = (wp + 1) & _maxWinMask;
    }
    _wrPtr = wp;
  }

  // Flush pending output — used in the main loop to avoid window wrap issues.
  void _writeBuf20() {
    var wp = _wrPtr;
    final up = _unpPtr & _maxWinMask;
    while (wp != up) {
      _out.add(_window[wp]);
      wp = (wp + 1) & _maxWinMask;
    }
    _wrPtr = wp;
  }

  // ---------------------------------------------------------------------------
  // Initialisation.
  // ---------------------------------------------------------------------------

  void _unpInitData15(bool solid) {
    if (!solid) {
      _avrPlcB = 0;
      _avrLn1 = 0;
      _avrLn2 = 0;
      _avrLn3 = 0;
      _numHuf = 0;
      _buf60 = 0;
      _avrPlc = 0x3500;
      _maxDist3 = 0x2001;
      _nhfb = 0x80;
      _nlzb = 0x80;
    }
    _flagsCnt = 0;
    _flagBuf = 0;
    _stMode = 0;
    _lCount = 0;
  }

  void _initHuff() {
    for (var i = 0; i < 256; i++) {
      _chSet[i] = i << 8;
      _chSetB[i] = i << 8;
      _chSetA[i] = i;
      _chSetC[i] = ((~i + 1) & 0xff) << 8;
    }
    _nToPl.fillRange(0, 256, 0);
    _nToPlB.fillRange(0, 256, 0);
    _nToPlC.fillRange(0, 256, 0);
    _corrHuff(_chSetB, _nToPlB);
  }

  void _corrHuff(Uint16List charSet, Uint8List numToPlace) {
    var idx = 0;
    for (var i = 7; i >= 0; i--) {
      for (var j = 0; j < 32; j++, idx++) {
        charSet[idx] = (charSet[idx] & 0xff00) | i;
      }
    }
    numToPlace.fillRange(0, 256, 0);
    for (var i = 6; i >= 0; i--) {
      numToPlace[i] = (7 - i) * 32;
    }
  }

  // ---------------------------------------------------------------------------
  // DecodeNum: decode a variable-length code using a distribution table.
  // ---------------------------------------------------------------------------

  int _decodeNum(
      int num, int startPos, List<int> decTab, List<int> posTab) {
    num &= 0xfff0;
    var i = 0;
    while (decTab[i] <= num) {
      startPos++;
      i++;
    }
    _faddbits(startPos);
    return (((num - (i > 0 ? decTab[i - 1] : 0)) >> (16 - startPos)) +
        posTab[startPos]);
  }

  // ---------------------------------------------------------------------------
  // CopyString15: LZ back-reference copy.
  // ---------------------------------------------------------------------------

  void _copyString15(int distance, int length) {
    _destUnpSize -= length;
    if ((!_firstWinDone && distance > _unpPtr) ||
        distance > _maxWinSize ||
        distance == 0) {
      // Corrupt / pre-window reference — emit zeros.
      while (length-- > 0) {
        _window[_unpPtr] = 0;
        _unpPtr = (_unpPtr + 1) & _maxWinMask;
      }
    } else {
      while (length-- > 0) {
        _window[_unpPtr] =
            _window[(_unpPtr - distance) & _maxWinMask];
        _unpPtr = (_unpPtr + 1) & _maxWinMask;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // GetFlagsBuf.
  // ---------------------------------------------------------------------------

  void _getFlagsBuf() {
    final flagsPlace =
        _decodeNum(_fgetbits(), _startHf2, _decHf2, _posHf2);
    if (flagsPlace >= _chSetC.length) return;

    int flags;
    int newFlagsPlace;
    while (true) {
      flags = _chSetC[flagsPlace];
      _flagBuf = (flags >> 8) & 0xff;
      newFlagsPlace = _nToPlC[flags & 0xff]++;
      flags = (flags & 0xff00) | ((flags + 1) & 0xff);
      if ((flags & 0xff) != 0) break;
      _corrHuff(_chSetC, _nToPlC);
    }
    _chSetC[flagsPlace] = _chSetC[newFlagsPlace];
    _chSetC[newFlagsPlace] = flags;
  }

  // ---------------------------------------------------------------------------
  // ShortLZ.
  // ---------------------------------------------------------------------------

  static const List<int> _shortLen1 = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
  static const List<int> _shortXor1 = [
    0, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe,
    0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0,
  ];
  static const List<int> _shortLen2 = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
  static const List<int> _shortXor2 = [
    0, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8,
    0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0, 0,
  ];

  int _getShortLen1(int pos) => pos == 1 ? _buf60 + 3 : _shortLen1[pos];
  int _getShortLen2(int pos) => pos == 3 ? _buf60 + 3 : _shortLen2[pos];

  void _shortLz() {
    _numHuf = 0;
    int length;

    var bitField = _fgetbits();
    if (_lCount == 2) {
      _faddbits(1);
      if (bitField >= 0x8000) {
        _copyString15(_lastDist, _lastLength);
        return;
      }
      bitField <<= 1;
      _lCount = 0;
    }

    bitField >>= 8;

    if (_avrLn1 < 37) {
      for (length = 0;; length++) {
        if (((bitField ^ _shortXor1[length]) &
                (~(0xff >> _getShortLen1(length)))) ==
            0) { break; }
      }
      _faddbits(_getShortLen1(length));
    } else {
      for (length = 0;; length++) {
        if (((bitField ^ _shortXor2[length]) &
                (~(0xff >> _getShortLen2(length)))) ==
            0) { break; }
      }
      _faddbits(_getShortLen2(length));
    }

    if (length >= 9) {
      if (length == 9) {
        _lCount++;
        _copyString15(_lastDist, _lastLength);
        return;
      }
      if (length == 14) {
        _lCount = 0;
        length = _decodeNum(_fgetbits(), _startL2, _decL2, _posL2) + 5;
        final distance = (_fgetbits() >> 1) | 0x8000;
        _faddbits(15);
        _lastLength = length;
        _lastDist = distance;
        _copyString15(distance, length);
        return;
      }

      _lCount = 0;
      final saveLength = length;
      final distance =
          _oldDist[(_oldDistPtr - (length - 9)) & 3];
      length = _decodeNum(_fgetbits(), _startL1, _decL1, _posL1) + 2;
      if (length == 0x101 && saveLength == 10) {
        _buf60 ^= 1;
        return;
      }
      if (distance > 256) length++;
      if (distance >= _maxDist3) length++;

      _oldDist[_oldDistPtr++] = distance;
      _oldDistPtr &= 3;
      _lastLength = length;
      _lastDist = distance;
      _copyString15(distance, length);
      return;
    }

    _lCount = 0;
    _avrLn1 += length;
    _avrLn1 -= _avrLn1 >> 4;

    final distancePlace =
        _decodeNum(_fgetbits(), _startHf2, _decHf2, _posHf2) & 0xff;
    var distance = _chSetA[distancePlace];
    if (distancePlace - 1 >= 0) {
      final last = _chSetA[distancePlace - 1];
      _chSetA[distancePlace] = last;
      _chSetA[distancePlace - 1] = distance;
    }
    length += 2;
    _oldDist[_oldDistPtr++] = ++distance;
    _oldDistPtr &= 3;
    _lastLength = length;
    _lastDist = distance;
    _copyString15(distance, length);
  }

  // ---------------------------------------------------------------------------
  // LongLZ.
  // ---------------------------------------------------------------------------

  void _longLz() {
    int length;
    int distance;
    int distancePlace, newDistancePlace;

    _numHuf = 0;
    _nlzb += 16;
    if (_nlzb > 0xff) {
      _nlzb = 0x90;
      _nhfb >>= 1;
    }
    final oldAvr2 = _avrLn2;

    var bitField = _fgetbits();
    if (_avrLn2 >= 122) {
      length = _decodeNum(bitField, _startL2, _decL2, _posL2);
    } else if (_avrLn2 >= 64) {
      length = _decodeNum(bitField, _startL1, _decL1, _posL1);
    } else if (bitField < 0x100) {
      length = bitField;
      _faddbits(16);
    } else {
      for (length = 0; ((bitField << length) & 0x8000) == 0; length++) {}
      _faddbits(length + 1);
    }

    _avrLn2 += length;
    _avrLn2 -= _avrLn2 >> 5;

    bitField = _fgetbits();
    if (_avrPlcB > 0x28ff) {
      distancePlace =
          _decodeNum(bitField, _startHf2, _decHf2, _posHf2);
    } else if (_avrPlcB > 0x6ff) {
      distancePlace =
          _decodeNum(bitField, _startHf1, _decHf1, _posHf1);
    } else {
      distancePlace =
          _decodeNum(bitField, _startHf0, _decHf0, _posHf0);
    }

    _avrPlcB += distancePlace;
    _avrPlcB -= _avrPlcB >> 8;
    while (true) {
      distance = _chSetB[distancePlace & 0xff];
      newDistancePlace = _nToPlB[distance & 0xff]++;
      distance = (distance & 0xff00) | ((distance + 1) & 0xff);
      if ((distance & 0xff) != 0) break;
      _corrHuff(_chSetB, _nToPlB);
    }

    _chSetB[distancePlace & 0xff] = _chSetB[newDistancePlace];
    _chSetB[newDistancePlace] = distance;

    distance = (((distance & 0xff00) | (_fgetbits() >> 8)) >> 1) & 0xffff;
    _faddbits(7);

    final oldAvr3 = _avrLn3;
    if (length != 1 && length != 4) {
      if (length == 0 && distance <= _maxDist3) {
        _avrLn3++;
        _avrLn3 -= _avrLn3 >> 8;
      } else if (_avrLn3 > 0) {
        _avrLn3--;
      }
    }
    length += 3;
    if (distance >= _maxDist3) length++;
    if (distance <= 256) length += 8;
    if (oldAvr3 > 0xb0 ||
        (_avrPlc >= 0x2a00 && oldAvr2 < 0x40)) {
      _maxDist3 = 0x7f00;
    } else {
      _maxDist3 = 0x2001;
    }
    _oldDist[_oldDistPtr++] = distance;
    _oldDistPtr &= 3;
    _lastLength = length;
    _lastDist = distance;
    _copyString15(distance, length);
  }

  // ---------------------------------------------------------------------------
  // HuffDecode.
  // ---------------------------------------------------------------------------

  void _huffDecode() {
    final bitField = _fgetbits();
    int bytePlace;

    if (_avrPlc > 0x75ff) {
      bytePlace = _decodeNum(bitField, _startHf4, _decHf4, _posHf4);
    } else if (_avrPlc > 0x5dff) {
      bytePlace = _decodeNum(bitField, _startHf3, _decHf3, _posHf3);
    } else if (_avrPlc > 0x35ff) {
      bytePlace = _decodeNum(bitField, _startHf2, _decHf2, _posHf2);
    } else if (_avrPlc > 0x0dff) {
      bytePlace = _decodeNum(bitField, _startHf1, _decHf1, _posHf1);
    } else {
      bytePlace = _decodeNum(bitField, _startHf0, _decHf0, _posHf0);
    }
    bytePlace &= 0xff;

    if (_stMode != 0) {
    if (bytePlace == 0 && bitField > 0xfff) { bytePlace = 0x100; }
      if (--bytePlace == -1) {
        final bf2 = _fgetbits();
        _faddbits(1);
        if ((bf2 & 0x8000) != 0) {
          _numHuf = 0;
          _stMode = 0;
          return;
        } else {
          final l = ((bf2 & 0x4000) != 0) ? 4 : 3;
          _faddbits(1);
          final d =
              _decodeNum(_fgetbits(), _startHf2, _decHf2, _posHf2);
          final dist = (d << 5) | (_fgetbits() >> 11);
          _faddbits(5);
          _copyString15(dist, l);
          return;
        }
      }
    } else {
      if (_numHuf++ >= 16 && _flagsCnt == 0) _stMode = 1;
    }

    _avrPlc += bytePlace;
    _avrPlc -= _avrPlc >> 8;
    _nhfb += 16;
    if (_nhfb > 0xff) {
      _nhfb = 0x90;
      _nlzb >>= 1;
    }

    _window[_unpPtr++] = (_chSet[bytePlace] >> 8) & 0xff;
    --_destUnpSize;

    int curByte;
    int newBytePlace;
    while (true) {
      curByte = _chSet[bytePlace];
      newBytePlace = _nToPl[curByte & 0xff]++;
      curByte = (curByte & 0xff00) | ((curByte + 1) & 0xff);
      if ((curByte & 0xff) > 0xa1) {
        _corrHuff(_chSet, _nToPl);
      } else {
        break;
      }
    }
    _chSet[bytePlace] = _chSet[newBytePlace];
    _chSet[newBytePlace] = curByte;
  }
}
