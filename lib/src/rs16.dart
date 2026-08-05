/// Reed-Solomon error correction over GF(2^16), ported from the RARLAB
/// UnRAR `RSCoder16` class (`rs16.cpp`).
///
/// RAR 5.0 recovery volumes (`*.rev`) encode data as 16-bit words in
/// GF(2^16), using a Cauchy generator matrix. Missing data units are
/// recovered by inverting the corresponding decoder matrix and applying it
/// to the surviving data and recovery streams.
library;

import 'dart:typed_data';

/// A Reed-Solomon encoder/decoder over GF(2^16) for RAR 5.0 recovery
/// records.
class Rs16 {
  /// Galois field size: `2^16 - 1` nonzero elements.
  static const int gfSize = 65535;

  /// Irreducible field-generator polynomial.
  static const int _generatorPoly = 0x1100B;

  /// Exponentiation table; see `gfInit` in `rs16.cpp`.
  final Uint16List _gfExp = Uint16List(4 * gfSize + 1);

  /// Logarithm table; see `gfInit` in `rs16.cpp`.
  ///
  /// 32-bit wide: `gfLog[0]` holds the special value `2*gfSize` (131070,
  /// above the 16-bit range) so products involving zero fall into the zeroed
  /// tail of `_gfExp` without a range check.
  final Uint32List _gfLog = Uint32List(gfSize + 1);

  /// Reusable buffer of logarithms of the current data block's words.
  Uint32List? _dataLog;

  int _nd = 0; // Number of data units.
  int _nr = 0; // Number of recovery units.
  int _ne = 0; // Number of erasures (decode only).

  /// `null` for encoding; validity flags for decoding.
  List<bool>? _validFlags;

  /// Cauchy coding/decoding matrix (`NR*ND` when encoding, inverted
  /// `NE*ND` matrix when decoding).
  final List<int> _mx = [];

  bool _tablesReady = false;

  /// Number of data units.
  int get dataCount => _nd;

  /// Number of recovery units.
  int get recCount => _nr;

  /// Number of erasures being decoded.
  int get erasures => _ne;

  /// Whether this instance was initialized for decoding.
  bool get decoding => _validFlags != null;

  /// Builds the exponent/logarithm tables (mirrors `RSCoder16::gfInit`).
  void _initTables() {
    if (_tablesReady) return;
    _tablesReady = true;
    var e = 1;
    for (var l = 0; l < gfSize; l++) {
      _gfLog[e] = l;
      _gfExp[l] = e;
      _gfExp[l + gfSize] = e; // Duplicate to avoid overflow checks.
      e <<= 1;
      if (e > gfSize) e ^= _generatorPoly;
    }
    // log(0)+log(x) must stay outside the usual table so products with 0
    // become 0 without a range check.
    _gfLog[0] = 2 * gfSize;
    for (var i = 2 * gfSize; i <= 4 * gfSize; i++) {
      _gfExp[i] = 0;
    }
  }

  /// Addition in the Galois field is XOR (`gfAdd`).
  static int gfAdd(int a, int b) => a ^ b;

  /// Multiplication in the Galois field (`gfMul`).
  int gfMul(int a, int b) => _gfExp[_gfLog[a] + _gfLog[b]];

  /// Inverse element in the Galois field (`gfInv`).
  int gfInv(int a) => a == 0 ? 0 : _gfExp[gfSize - _gfLog[a]];

  /// Initializes the coder for [dataCount] data units and [recCount]
  /// recovery units.
  ///
  /// When [validityFlags] is non-null the instance is set up for decoding:
  /// flags are indexed over all `dataCount + recCount` units, `true` marks a
  /// valid (present) unit. Returns `false` (matching the C) when decoding is
  /// impossible: nothing missing, no valid recovery unit, or more erasures
  /// than recovery units.
  bool init(int dataCount, int recCount, {List<bool>? validityFlags}) {
    _initTables();
    _nd = dataCount;
    _nr = recCount;
    _ne = 0;
    _validFlags = validityFlags;

    if (validityFlags != null) {
      var validEcc = 0;
      for (var i = 0; i < dataCount; i++) {
        if (!validityFlags[i]) _ne++;
      }
      for (var i = dataCount; i < dataCount + recCount; i++) {
        if (validityFlags[i]) validEcc++;
      }
      if (_ne == 0 || validEcc == 0 || _ne > validEcc) return false;
    }

    if (dataCount + recCount > gfSize ||
        dataCount == 0 ||
        recCount == 0) {
      return false;
    }

    _mx.clear();
    if (validityFlags != null) {
      _makeDecoderMatrix();
      _invertDecoderMatrix();
    } else {
      _makeEncoderMatrix();
    }
    return true;
  }

  /// Builds the Cauchy encoder generator matrix. Skips trivial "1" diagonal
  /// rows, which would just copy source data to destination.
  void _makeEncoderMatrix() {
    for (var i = 0; i < _nr; i++) {
      for (var j = 0; j < _nd; j++) {
        _mx.add(gfInv(gfAdd(i + _nd, j)));
      }
    }
  }

  /// Builds the Cauchy decoder matrix. Includes rows only for broken data
  /// units, replacing each by the first available valid recovery row.
  void _makeDecoderMatrix() {
    for (var flag = 0, r = _nd; flag < _nd; flag++) {
      if (!_validFlags![flag]) {
        while (!_validFlags![r]) {
          r++;
        }
        for (var j = 0; j < _nd; j++) {
          _mx.add(gfInv(gfAdd(r, j)));
        }
        r++;
      }
    }
  }

  /// Applies Gauss-Jordan elimination to find the inverse of the decoder
  /// matrix (mirrors `RSCoder16::InvertDecoderMatrix`).
  ///
  /// The result is the inverse matrix in `_mx`, indexed by broken data unit
  /// (in increasing flag order). The intermediate matrix `mi` starts as the
  /// identity restricted to the broken columns; trivial rows matching valid
  /// data units are folded in before eliminating.
  void _invertDecoderMatrix() {
    final mi = List<int>.filled(_ne * _nd, 0);
    for (var kr = 0, kf = 0; kr < _ne; kr++, kf++) {
      while (_validFlags![kf]) {
        kf++;
      }
      mi[kr * _nd + kf] = 1;
    }

    for (var kr = 0, kf = 0; kf < _nd; kr++, kf++) {
      while (kf < _nd && _validFlags![kf]) {
        for (var i = 0; i < _ne; i++) {
          mi[i * _nd + kf] ^= _mx[i * _nd + kf];
        }
        kf++;
      }
      if (kf == _nd) break;

      final pInv = gfInv(_mx[kr * _nd + kf]);
      for (var i = 0; i < _nd; i++) {
        _mx[kr * _nd + i] = gfMul(_mx[kr * _nd + i], pInv);
        mi[kr * _nd + i] = gfMul(mi[kr * _nd + i], pInv);
      }

      for (var i = 0; i < _ne; i++) {
        if (i != kr) {
          final mik = _mx[i * _nd + kf];
          for (var j = 0; j < _nd; j++) {
            _mx[i * _nd + j] ^= gfMul(_mx[kr * _nd + j], mik);
            mi[i * _nd + j] ^= gfMul(mi[kr * _nd + j], mik);
          }
        }
      }
    }

    // Copy data to main matrix.
    for (var i = 0; i < _ne * _nd; i++) {
      _mx[i] = mi[i];
    }
  }

  /// Applies data unit [dataNum] to every output unit in [outputs].
  ///
  /// When encoding, the outputs are the `recCount` recovery (ECC) streams;
  /// when decoding, they are the `erasures` recovered-data accumulators.
  /// Each 16-bit word of [data] (taken from [dataOffset] over [dataLength]
  /// bytes) is multiplied by the matrix coefficient and XORed into the
  /// corresponding output word at [outputOffset]. The caller must zero the
  /// outputs before the first data unit of a chunk.
  ///
  /// [dataLength] may be odd: the final byte is treated as zero (matching
  /// the C which only processes whole 16-bit words).
  void updateEccAll(
    int dataNum,
    Uint8List data,
    int dataOffset,
    int dataLength,
    List<Uint8List> outputs,
    int outputOffset,
  ) {
    final count = decoding ? _ne : _nr;

    // Precompute logarithms of the data words once per data unit.
    final words = (dataLength + 1) >> 1;
    var logs = _dataLog;
    if (logs == null || logs.length < words) {
      logs = Uint32List(words);
      _dataLog = logs;
    }
    for (var i = 0; i + 1 < dataLength; i += 2) {
      final d = data[dataOffset + i] | (data[dataOffset + i + 1] << 8);
      logs[i >> 1] = _gfLog[d];
    }
    if (dataLength.isOdd) {
      logs[dataLength >> 1] = _gfLog[data[dataOffset + dataLength - 1]];
    }

    for (var o = 0; o < count; o++) {
      final ml = _gfLog[_mx[o * _nd + dataNum]];
      final out = outputs[o];
      for (var i = 0; i + 1 < dataLength; i += 2) {
        final r = _gfExp[ml + logs[i >> 1]];
        out[outputOffset + i] ^= r & 0xff;
        out[outputOffset + i + 1] ^= (r >> 8) & 0xff;
      }
      if (dataLength.isOdd) {
        final r = _gfExp[ml + logs[dataLength >> 1]];
        out[outputOffset + dataLength - 1] ^= r & 0xff;
      }
    }
  }
}
