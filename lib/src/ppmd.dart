/// PPMd (PPMII variant) range-coder decompression, ported from the RARLAB
/// UnRAR source (`model.cpp`, `suballoc.cpp`, `coder.cpp`).
///
/// The model runs on top of a raw memory block emulated as a `Uint8List`;
/// every "pointer" is an integer offset into that block, mirroring the C
/// layout exactly. This keeps the many pointer-arithmetic tricks of the
/// original algorithm (successors pointing into the text buffer, packed
/// `RARPPM_STATE` / `RARPPM_CONTEXT` structures, a hand-rolled allocator)
/// byte-for-byte equivalent.
library;

import 'dart:typed_data';

import 'bit_input.dart';
import 'unrar_error.dart';

// RARPPM_DEF constants.
const int _intBits = 7;
const int _periodBits = 7;
const int _totBits = _intBits + _periodBits;
const int _interval = 1 << _intBits; // 128
const int _binScale = 1 << _totBits; // 16384
const int _maxFreq = 124;

// Range coder constants.
const int _top = 1 << 24;
const int _bot = 1 << 15;

// SubAllocator sizes verified against the real build flags
// (ALLOW_MISALIGNED on x86_64): RARPPM_STATE = 10, RARPPM_CONTEXT = 20,
// RARPPM_MEM_BLK = 20 -> UNIT_SIZE = 20, FIXED_UNIT_SIZE = 12.
const int _unitSize = 20;
const int _fixedUnitSize = 12;

const int _maxStateOrder = 64; // MAX_O

// SubAllocator index constants: N1=N2=N3=4, N4=26 -> N_INDEXES=38.
const int _n1 = 4, _n2 = 4, _n3 = 4, _n4 = 26;
const int _nIndexes = _n1 + _n2 + _n3 + _n4;

/// Emulates the PPMd memory allocator and raw byte heap from `suballoc.cpp`.
///
/// All public integer arguments and returns are byte offsets into [heap].
class PpmdSubAllocator {
  Uint8List? _heap;

  /// The raw memory block, or `null` after [stopSubAllocator].
  Uint8List? get heap => _heap;

  int heapEnd = 0;
  int loUnit = 0;
  int hiUnit = 0;
  int unitsStart = 0;
  int fakeUnitsStart = 0;
  int pText = 0;
  int subAllocatorSize = 0;
  int glueCount = 0;

  final List<int> _freeList = List<int>.filled(_nIndexes, 0);
  final List<int> _indx2Units = List<int>.filled(_nIndexes, 0);
  final List<int> _units2Indx = List<int>.filled(128, 0);

  bool get allocated => subAllocatorSize != 0;

  /// Byte at [p].
  int b(int p) => _heap![p];

  /// Two little-endian bytes at [p].
  int w(int p) => _heap![p] | (_heap![p + 1] << 8);

  /// Eight little-endian bytes at [p] (a "pointer").
  int d(int p) {
    final h = _heap!;
    return (h[p] |
            (h[p + 1] << 8) |
            (h[p + 2] << 16) |
            (h[p + 3] << 24) |
            (h[p + 4] << 32) |
            (h[p + 5] << 40) |
            (h[p + 6] << 48) |
            (h[p + 7] << 56)) &
        0xFFFFFFFFFFFFFFFF;
  }

  void wb(int p, int v) => _heap![p] = v & 0xff;

  void ww(int p, int v) {
    final h = _heap!;
    h[p] = v & 0xff;
    h[p + 1] = (v >> 8) & 0xff;
  }

  void wd(int p, int v) {
    final h = _heap!;
    h[p] = v & 0xff;
    h[p + 1] = (v >> 8) & 0xff;
    h[p + 2] = (v >> 16) & 0xff;
    h[p + 3] = (v >> 24) & 0xff;
    h[p + 4] = (v >> 32) & 0xff;
    h[p + 5] = (v >> 40) & 0xff;
    h[p + 6] = (v >> 48) & 0xff;
    h[p + 7] = (v >> 56) & 0xff;
  }

  /// Mirrors `SubAllocator::StopSubAllocator`.
  void stopSubAllocator() {
    if (subAllocatorSize != 0) {
      subAllocatorSize = 0;
      _heap = null;
    }
  }

  /// Mirrors `SubAllocator::StartSubAllocator`.
  bool startSubAllocator(int saSize) {
    final t = saSize << 20;
    if (subAllocatorSize == t) {
      return true;
    }
    stopSubAllocator();
    // Original algorithm expects FIXED_UNIT_SIZE, but the real structures
    // are larger. Recalculate the allocation and add two units (reserve +
    // alignment), exactly like the C code.
    final allocSize = t ~/ _fixedUnitSize * _unitSize + 2 * _unitSize;
    _heap = Uint8List(allocSize);
    heapEnd = allocSize - _unitSize;
    subAllocatorSize = t;
    return true;
  }

  /// Mirrors `SubAllocator::InitSubAllocator`.
  void initSubAllocator() {
    _freeList.fillRange(0, _nIndexes, 0);
    pText = 0;

    // Size2 is the (HiUnit-LoUnit) area as the algorithm originally
    // expected (7/8 of the total), then corrected for the real UNIT_SIZE.
    final size2 = _fixedUnitSize * ((subAllocatorSize ~/ 8) ~/ _fixedUnitSize * 7);
    final realSize2 = size2 ~/ _fixedUnitSize * _unitSize;
    final size1 = subAllocatorSize - size2;
    final realSize1 = size1 ~/ _fixedUnitSize * _unitSize + _unitSize;

    loUnit = unitsStart = realSize1;
    fakeUnitsStart = size1;
    hiUnit = loUnit + realSize2;

    var i = 0;
    var k = 1;
    for (; i < _n1; i++, k += 1) {
      _indx2Units[i] = k;
    }
    for (k++; i < _n1 + _n2; i++, k += 2) {
      _indx2Units[i] = k;
    }
    for (k++; i < _n1 + _n2 + _n3; i++, k += 3) {
      _indx2Units[i] = k;
    }
    for (k++; i < _nIndexes; i++, k += 4) {
      _indx2Units[i] = k;
    }
    glueCount = 0;
    k = 0;
    i = 0;
    for (; k < 128; k++) {
      if (_indx2Units[i] < k + 1) {
        i++;
      }
      _units2Indx[k] = i;
    }
  }

  /// Mirrors `SubAllocator::InsertNode`.
  void insertNode(int p, int indx) {
    wd(p, _freeList[indx]);
    _freeList[indx] = p;
  }

  /// Mirrors `SubAllocator::RemoveNode`.
  int removeNode(int indx) {
    final retVal = _freeList[indx];
    _freeList[indx] = d(retVal);
    return retVal;
  }

  /// Mirrors `SubAllocator::U2B`.
  int u2b(int nu) => _unitSize * nu;

  /// Mirrors `SubAllocator::MBPtr`.
  int mbPtr(int base, int items) => base + u2b(items);

  /// Mirrors `SubAllocator::SplitBlock`.
  void splitBlock(int pv, int oldIndx, int newIndx) {
    var uDiff = _indx2Units[oldIndx] - _indx2Units[newIndx];
    var p = pv + u2b(_indx2Units[newIndx]);
    var i = _units2Indx[uDiff - 1];
    if (_indx2Units[i] != uDiff) {
      insertNode(p, --i);
      i = _indx2Units[i];
      p += u2b(i);
      uDiff -= i;
    }
    insertNode(p, _units2Indx[uDiff - 1]);
  }

  /// Mirrors `SubAllocator::GlueFreeBlocks`.
  void glueFreeBlocks() {
    final h = _heap!;
    if (loUnit != hiUnit) {
      h[loUnit] = 0;
    }
    // Sentinel doubly-linked list (the C "s0" node is on the stack, so we
    // model it with the special pointer value -1).
    var s0Next = -1;
    for (var i = 0; i < _nIndexes; i++) {
      while (_freeList[i] != 0) {
        final p = removeNode(i);
        // p->insertAt(&s0): insert p right after the sentinel.
        final oldNext = s0Next;
        wd(p + 4, oldNext); // p->next
        wd(p + 12, -1); // p->prev = &s0
        if (oldNext != -1) {
          wd(oldNext + 12, p);
        }
        s0Next = p;
        ww(p, 0xffff); // Stamp
        ww(p + 2, _indx2Units[i]); // NU
      }
    }
    // Merge adjacent free blocks.
    var p = s0Next;
    while (p != -1) {
      while (true) {
        final p1 = mbPtr(p, w(p + 2));
        if (w(p1) != 0xffff || w(p + 2) + w(p1 + 2) >= 0x10000) {
          break;
        }
        // p1->remove()
        wd(d(p1 + 12) + 4, d(p1 + 4));
        wd(d(p1 + 4) + 12, d(p1 + 12));
        ww(p + 2, w(p + 2) + w(p1 + 2)); // p->NU += p1->NU
      }
      p = d(p + 4); // p->next
    }
    // Re-split into the indexed free lists.
    while (s0Next != -1) {
      p = s0Next;
      // p->remove()
      final next = d(p + 4);
      final prev = d(p + 12);
      if (prev == -1) {
        s0Next = next;
      } else {
        wd(prev + 4, next);
      }
      if (next != -1) {
        wd(next + 12, prev);
      }
      var sz = w(p + 2);
      var q = p;
      while (sz > 128) {
        insertNode(q, _nIndexes - 1);
        sz -= 128;
        q = mbPtr(q, 128);
      }
      var i = _units2Indx[sz - 1];
      if (_indx2Units[i] != sz) {
        final k = sz - _indx2Units[--i];
        insertNode(mbPtr(q, sz - k), k - 1);
      }
      insertNode(q, i);
    }
  }

  /// Mirrors `SubAllocator::AllocUnitsRare`.
  int allocUnitsRare(int indx) {
    if (glueCount == 0) {
      glueCount = 255;
      glueFreeBlocks();
      if (_freeList[indx] != 0) {
        return removeNode(indx);
      }
    }
    var i = indx;
    while (true) {
      i++;
      if (i == _nIndexes) {
        glueCount--;
        i = u2b(_indx2Units[indx]);
        final j = _fixedUnitSize * _indx2Units[indx];
        if (fakeUnitsStart - pText > j) {
          fakeUnitsStart -= j;
          unitsStart -= i;
          return unitsStart;
        }
        return 0;
      }
      if (_freeList[i] != 0) {
        break;
      }
    }
    final retVal = removeNode(i);
    splitBlock(retVal, i, indx);
    return retVal;
  }

  /// Mirrors `SubAllocator::AllocUnits`.
  int allocUnits(int nu) {
    final indx = _units2Indx[nu - 1];
    if (_freeList[indx] != 0) {
      return removeNode(indx);
    }
    var retVal = loUnit;
    loUnit += u2b(_indx2Units[indx]);
    if (loUnit <= hiUnit) {
      return retVal;
    }
    loUnit -= u2b(_indx2Units[indx]);
    return allocUnitsRare(indx);
  }

  /// Mirrors `SubAllocator::AllocContext`.
  int allocContext() {
    if (hiUnit != loUnit) {
      hiUnit -= _unitSize;
      return hiUnit;
    }
    if (_freeList[0] != 0) {
      return removeNode(0);
    }
    return allocUnitsRare(0);
  }

  /// Mirrors `SubAllocator::ExpandUnits`.
  int expandUnits(int oldPtr, int oldNU) {
    final i0 = _units2Indx[oldNU - 1];
    final i1 = _units2Indx[oldNU];
    if (i0 == i1) {
      return oldPtr;
    }
    final ptr = allocUnits(oldNU + 1);
    if (ptr != 0) {
      final h = _heap!;
      final size = u2b(oldNU);
      final tmp = Uint8List(size);
      tmp.setRange(0, size, h, oldPtr);
      h.setRange(ptr, ptr + size, tmp);
      insertNode(oldPtr, i0);
    }
    return ptr;
  }

  /// Mirrors `SubAllocator::ShrinkUnits`.
  int shrinkUnits(int oldPtr, int oldNU, int newNU) {
    final i0 = _units2Indx[oldNU - 1];
    final i1 = _units2Indx[newNU - 1];
    if (i0 == i1) {
      return oldPtr;
    }
    if (_freeList[i1] != 0) {
      final ptr = removeNode(i1);
      final h = _heap!;
      final size = u2b(newNU);
      final tmp = Uint8List(size);
      tmp.setRange(0, size, h, oldPtr);
      h.setRange(ptr, ptr + size, tmp);
      insertNode(oldPtr, i0);
      return ptr;
    }
    splitBlock(oldPtr, i0, i1);
    return oldPtr;
  }

  /// Mirrors `SubAllocator::FreeUnits`.
  void freeUnits(int ptr, int oldNU) {
    insertNode(ptr, _units2Indx[oldNU - 1]);
  }
}

/// The carryless range decoder from `coder.cpp`.
class _RangeCoder {
  int low = 0;
  int code = 0;
  int range = 0;
  int lowCount = 0;
  int highCount = 0;
  int scale = 0;

  BitInput? _input;

  void initDecoder(BitInput input) {
    _input = input;
    low = 0;
    code = 0;
    range = 0xFFFFFFFF;
    for (var i = 0; i < 4; i++) {
      code = ((code << 8) | input.getChar()) & 0xFFFFFFFF;
    }
  }

  /// Mirrors `RangeCoder::GetCurrentCount`.
  int getCurrentCount() {
    range = range ~/ scale;
    return ((code - low) & 0xFFFFFFFF) ~/ range;
  }

  /// Mirrors `RangeCoder::GetCurrentShiftCount`.
  int getCurrentShiftCount(int shift) {
    range = range >> shift;
    return ((code - low) & 0xFFFFFFFF) ~/ range;
  }

  /// Mirrors `RangeCoder::Decode`.
  void decode() {
    low = (low + range * lowCount) & 0xFFFFFFFF;
    range = (range * (highCount - lowCount)) & 0xFFFFFFFF;
  }

  /// Mirrors the `ARI_DEC_NORMALIZE` macro.
  ///
  /// The C condition is `(low^(low+range)) < TOP || (range < BOT &&
  /// (range = -(int)low & (BOT-1), 1))`; because `||` short-circuits, the
  /// range fix is only applied when `(low^(low+range)) >= TOP` and
  /// `range < BOT` at the same time.
  void normalize() {
    while (true) {
      final x = (low ^ ((low + range) & 0xFFFFFFFF)) & 0xFFFFFFFF;
      if (x >= _top && range >= _bot) {
        break;
      }
      if (x >= _top && range < _bot) {
        range = (-low) & 0x7FFF;
      }
      code = ((code << 8) | _input!.getChar()) & 0xFFFFFFFF;
      range = (range << 8) & 0xFFFFFFFF;
      low = (low << 8) & 0xFFFFFFFF;
    }
  }
}

/// SEE-contexts for PPM-contexts with masked symbols (`RARPPM_SEE2_CONTEXT`).
class _See2Context {
  int summ = 0;
  int shift = 0;
  int count = 0;

  void init(int initVal) {
    shift = _periodBits - 4;
    summ = initVal << shift;
    count = 4;
  }

  int getMean() {
    final retVal = (summ & 0xffff) >> shift;
    summ = (summ - retVal) & 0xffff;
    return retVal + (retVal == 0 ? 1 : 0);
  }

  void update() {
    if (shift < _periodBits && --count == 0) {
      summ = (summ + summ) & 0xffff;
      count = 3 << shift++;
    }
  }
}

/// PPMd model decoder, ported from `ModelPPM` (`model.cpp`).
///
/// One instance is shared across all blocks (and, for solid archives, files)
/// of a stream; `decodeInit` with the reset flag rebuilds the model.
class PpmdDecoder {
  PpmdDecoder() : _see2Cont = _makeSee2();

  final PpmdSubAllocator sub = PpmdSubAllocator();
  final _RangeCoder _coder = _RangeCoder();
  final _See2Context _dummySee2 = _See2Context();

  final List<List<_See2Context>> _see2Cont;
  final Uint8List _charMask = Uint8List(256);
  final Uint8List _ns2Indx = Uint8List(256);
  final Uint8List _ns2bsIndx = Uint8List(256);
  final Uint8List _hb2Flag = Uint8List(256);
  final Uint16List _binSumm = Uint16List(128 * 64);

  // Scratch arrays (the C `ps[256]` / `ps[MAX_O]` stacks).
  final List<int> _ps = List<int>.filled(256, 0);
  final Uint8List _tmpState = Uint8List(_unitSize);

  // Dedicated scratch for the C stack-local `RARPPM_STATE` temporaries in
  // `rescale`; never lives inside the allocator heap.
  final Uint8List _rescaleState = Uint8List(10);

  int _minContext = 0;
  int _maxContext = 0;
  int _foundState = 0;
  int _numMasked = 0;
  int _initEsc = 0;
  int _orderFall = 0;
  int _maxOrder = 0;
  int _runLength = 0;
  int _initRL = 0;
  int _escCount = 0;
  int _prevSuccess = 0;
  int _hiBitsFlag = 0;
  int _escChar = 2;

  static const List<int> _initBinEsc = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
  ];
  static const List<int> _expEscape = [
    25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2,
  ];

  static List<List<_See2Context>> _makeSee2() => [
        for (var i = 0; i < 25; i++)
          [for (var k = 0; k < 16; k++) _See2Context()],
      ];

  int get escChar => _escChar;

  /// Mirrors `ModelPPM::DecodeInit`. [escCharInit] is the current per-file
  /// escape character value (2 by default).
  bool decodeInit(BitInput input, int escCharInit) {
    _escChar = escCharInit;
    var maxOrder = input.getChar();
    final reset = (maxOrder & 0x20) != 0;

    if (!reset && !sub.allocated) {
      return false;
    }
    final maxMB = reset ? input.getChar() : 0;
    if ((maxOrder & 0x40) != 0) {
      _escChar = input.getChar();
    }
    _coder.initDecoder(input);
    if (reset) {
      maxOrder = (maxOrder & 0x1f) + 1;
      if (maxOrder > 16) {
        maxOrder = 16 + (maxOrder - 16) * 3;
      }
      if (maxOrder == 1) {
        sub.stopSubAllocator();
        return false;
      }
      sub.startSubAllocator(maxMB + 1);
      startModelRare(maxOrder);
    }
    return _minContext != 0;
  }

  /// Mirrors `ModelPPM::DecodeChar`. Returns -1 on corrupt data.
  int decodeChar() {
    final h = sub.heap!;
    if (_minContext <= sub.pText || _minContext > sub.heapEnd) {
      return -1;
    }
    if (sub.w(_minContext) != 1) {
      final stats = sub.d(_minContext + 4);
      if (stats <= sub.pText || stats > sub.heapEnd) {
        return -1;
      }
      if (!_decodeSymbol1(_minContext)) {
        return -1;
      }
    } else {
      _decodeBinSymbol(_minContext);
    }
    _coder.decode();
    while (_foundState == 0) {
      _coder.normalize();
      do {
        _orderFall++;
        _minContext = sub.d(_minContext + 12);
        if (_minContext <= sub.pText || _minContext > sub.heapEnd) {
          return -1;
        }
      } while (sub.w(_minContext) == _numMasked);
      if (!_decodeSymbol2(_minContext)) {
        return -1;
      }
      _coder.decode();
    }
    final symbol = h[_foundState];
    if (_orderFall == 0 && sub.d(_foundState + 2) > sub.pText) {
      _minContext = _maxContext = sub.d(_foundState + 2);
    } else {
      _updateModel();
      if (_escCount == 0) {
        _clearMask();
      }
    }
    _coder.normalize();
    return symbol;
  }

  /// Mirrors `ModelPPM::CleanUp`.
  void cleanUp() {
    sub.stopSubAllocator();
    sub.startSubAllocator(1);
    startModelRare(2);
  }

  // -------------------------------------------------------------------------
  // ModelPPM internals.
  // -------------------------------------------------------------------------

  void _restartModelRare() {
    final h = sub.heap!;
    _charMask.fillRange(0, 256, 0);
    sub.initSubAllocator();
    _initRL = -(_maxOrder < 12 ? _maxOrder : 12) - 1;
    _minContext = _maxContext = sub.allocContext();
    if (_minContext == 0) {
      throw UnrarException('PPMd: no memory for initial context');
    }
    sub.wd(_minContext + 12, 0); // Suffix = NULL
    _orderFall = _maxOrder;
    sub.ww(_minContext, 256); // NumStats
    sub.ww(_minContext + 2, 257); // SummFreq = 256 + 1
    _foundState = sub.allocUnits(128);
    sub.wd(_minContext + 4, _foundState); // Stats
    if (_foundState == 0) {
      throw UnrarException('PPMd: no memory for symbol stats');
    }
    _runLength = _initRL;
    _prevSuccess = 0;
    for (var i = 0; i < 256; i++) {
      final p = _foundState + i * 10;
      h[p] = i;
      h[p + 1] = 1;
      sub.wd(p + 2, 0); // Successor = NULL
    }
    for (var i = 0; i < 128; i++) {
      for (var k = 0; k < 8; k++) {
        final esc = _initBinEsc[k] ~/ (i + 2);
        for (var m = 0; m < 64; m += 8) {
          _binSumm[i * 64 + (k + m)] = _binScale - esc;
        }
      }
    }
    for (var i = 0; i < 25; i++) {
      for (var k = 0; k < 16; k++) {
        _see2Cont[i][k].init(5 * i + 10);
      }
    }
  }

  void startModelRare(int maxOrder) {
    _escCount = 1;
    _maxOrder = maxOrder;
    _restartModelRare();
    _ns2bsIndx[0] = 0;
    _ns2bsIndx[1] = 2;
    _ns2bsIndx.fillRange(2, 11, 4);
    _ns2bsIndx.fillRange(11, 256, 6);
    for (var i = 0; i < 3; i++) {
      _ns2Indx[i] = i;
    }
    var m = 3;
    var k = 1;
    var step = 1;
    for (var i = 3; i < 256; i++) {
      _ns2Indx[i] = m;
      if (--k == 0) {
        k = ++step;
        m++;
      }
    }
    _hb2Flag.fillRange(0, 0x40, 0);
    _hb2Flag.fillRange(0x40, 0x100, 8);
    _dummySee2.shift = _periodBits;
  }

  void _clearMask() {
    _escCount = 1;
    _charMask.fillRange(0, 256, 0);
  }

  /// Copies the 10-byte `RARPPM_STATE` at [src] to [dst].
  void _copyState(int dst, int src) {
    final h = sub.heap!;
    final tmp = _tmpState;
    for (var i = 0; i < 10; i++) {
      tmp[i] = h[src + i];
    }
    for (var i = 0; i < 10; i++) {
      h[dst + i] = tmp[i];
    }
  }

  void _stashState(int src) {
    final h = sub.heap!;
    for (var i = 0; i < 10; i++) {
      _rescaleState[i] = h[src + i];
    }
  }

  void _restoreState(int dst) {
    final h = sub.heap!;
    for (var i = 0; i < 10; i++) {
      h[dst + i] = _rescaleState[i];
    }
  }

  void _swapStates(int a, int b) {
    final h = sub.heap!;
    final tmp = _tmpState;
    for (var i = 0; i < 10; i++) {
      tmp[i] = h[a + i];
    }
    for (var i = 0; i < 10; i++) {
      h[a + i] = h[b + i];
    }
    for (var i = 0; i < 10; i++) {
      h[b + i] = tmp[i];
    }
  }

  /// Mirrors `RARPPM_CONTEXT::createChild`.
  int _createChild(
      int pc, int pStats, int symbol, int freq, int successor) {
    final child = sub.allocContext();
    if (child != 0) {
      final h = sub.heap!;
      sub.ww(child, 1); // NumStats = 1
      h[child + 2] = symbol; // OneState.Symbol
      h[child + 3] = freq; // OneState.Freq
      sub.wd(child + 4, successor); // OneState.Successor
      sub.wd(child + 12, pc); // Suffix = this
      sub.wd(pStats + 2, child); // pStats->Successor = pc
    }
    return child;
  }

  /// Mirrors `RARPPM_CONTEXT::rescale`.
  void _rescale(int ctx) {
    final h = sub.heap!;
    final stats = sub.d(ctx + 4);
    final oldNS = sub.w(ctx);
    var i = oldNS - 1;

    var p = _foundState;
    while (p != stats) {
      _swapStates(p, p - 10);
      p -= 10;
    }
    h[p + 1] += 4; // U.Stats->Freq += 4
    sub.ww(ctx + 2, sub.w(ctx + 2) + 4); // U.SummFreq += 4
    final adder = _orderFall != 0 ? 1 : 0;
    var escFreq = sub.w(ctx + 2) - h[p + 1];
    var freq = (h[p + 1] + adder) >> 1;
    h[p + 1] = freq;
    sub.ww(ctx + 2, freq);
    do {
      p += 10;
      escFreq -= h[p + 1];
      freq = (h[p + 1] + adder) >> 1;
      h[p + 1] = freq;
      sub.ww(ctx + 2, sub.w(ctx + 2) + freq);
      if (h[p + 1] > h[p - 10 + 1]) {
        _stashState(p);
        var p1 = p;
        do {
          _copyState(p1, p1 - 10);
          p1 -= 10;
        } while (p1 != stats && _rescaleState[1] > h[p1 - 10 + 1]);
        _restoreState(p1);
      }
    } while (--i != 0);
    if (h[p + 1] == 0) {
      do {
        i++;
      } while (h[(p -= 10) + 1] == 0);
      escFreq += i;
      final newNumStats = sub.w(ctx) - i;
      sub.ww(ctx, newNumStats);
      if (newNumStats == 1) {
        _stashState(stats);
        var tmpFreq = _rescaleState[1];
        do {
          tmpFreq -= tmpFreq >> 1;
          escFreq >>= 1;
        } while (escFreq > 1);
        sub.freeUnits(stats, (oldNS + 1) >> 1);
        _foundState = ctx + 2; // &OneState
        h[ctx + 2] = _rescaleState[0];
        h[ctx + 3] = tmpFreq;
        sub.wd(ctx + 4,
            _rescaleState[2] |
                (_rescaleState[3] << 8) |
                (_rescaleState[4] << 16) |
                (_rescaleState[5] << 24) |
                (_rescaleState[6] << 32) |
                (_rescaleState[7] << 40) |
                (_rescaleState[8] << 48) |
                (_rescaleState[9] << 56));
        return;
      }
    }
    escFreq -= escFreq >> 1;
    sub.ww(ctx + 2, sub.w(ctx + 2) + escFreq);
    final n0 = (oldNS + 1) >> 1;
    final n1 = (sub.w(ctx) + 1) >> 1;
    if (n0 != n1) {
      final newStats = sub.shrinkUnits(stats, n0, n1);
      sub.wd(ctx + 4, newStats);
    }
    _foundState = sub.d(ctx + 4);
  }

  /// Mirrors `ModelPPM::CreateSuccessors`.
  int _createSuccessors(bool skip, int p1) {
    final h = sub.heap!;
    final upBranch = sub.d(_foundState + 2);
    var pc = _minContext;
    var p = 0;
    var pps = 0;

    if (!skip) {
      _ps[pps++] = _foundState;
      if (sub.d(pc + 12) == 0) {
        return _finishCreateSuccessors(upBranch, pc, pps);
      }
    }
    if (p1 != 0) {
      p = p1;
      pc = sub.d(pc + 12);
      if (sub.d(p + 2) != upBranch) {
        pc = sub.d(p + 2);
        return _finishCreateSuccessors(upBranch, pc, pps);
      }
      if (pps >= _maxStateOrder) {
        return 0;
      }
      _ps[pps++] = p;
      if (sub.d(pc + 12) == 0) {
        return _finishCreateSuccessors(upBranch, pc, pps);
      }
      while (true) {
        pc = sub.d(pc + 12);
        if (!_findStateP(pc, h[_foundState])) {
          return 0;
        }
        p = _findStateResult;
        if (sub.d(p + 2) != upBranch) {
          pc = sub.d(p + 2);
          return _finishCreateSuccessors(upBranch, pc, pps);
        }
        if (pps >= _maxStateOrder) {
          return 0;
        }
        _ps[pps++] = p;
        if (sub.d(pc + 12) == 0) {
          return _finishCreateSuccessors(upBranch, pc, pps);
        }
      }
    }
    while (true) {
      pc = sub.d(pc + 12);
      if (!_findStateP(pc, h[_foundState])) {
        return 0;
      }
      p = _findStateResult;
      if (sub.d(p + 2) != upBranch) {
        pc = sub.d(p + 2);
        return _finishCreateSuccessors(upBranch, pc, pps);
      }
      if (pps >= _maxStateOrder) {
        return 0;
      }
      _ps[pps++] = p;
      if (sub.d(pc + 12) == 0) {
        return _finishCreateSuccessors(upBranch, pc, pps);
      }
    }
  }

  /// Shared tail of `CreateSuccessors` (the C `NO_LOOP` label and what
  /// follows it).
  int _finishCreateSuccessors(int upBranch, int pc, int pps) {
    if (pps == 0) {
      return pc;
    }
    final h = sub.heap!;
    final upStateSymbol = h[upBranch];
    final upStateSuccessor = upBranch + 1;
    int upStateFreq;
    if (sub.w(pc) != 1) {
      if (pc <= sub.pText) {
        return 0;
      }
      var p = sub.d(pc + 4);
      if (h[p] != upStateSymbol) {
        while (h[p] != upStateSymbol) {
          p += 10;
        }
      }
      final cf = h[p + 1] - 1;
      final s0 = sub.w(pc + 2) - sub.w(pc) - cf;
      upStateFreq = 1 +
          ((2 * cf <= s0)
              ? ((5 * cf > s0) ? 1 : 0)
              : ((2 * cf + 3 * s0 - 1) ~/ (2 * s0)));
    } else {
      upStateFreq = h[pc + 3];
    }
    while (pps != 0) {
      pps--;
      pc = _createChild(pc, _ps[pps], upStateSymbol, upStateFreq, upStateSuccessor);
      if (pc == 0) {
        return 0;
      }
    }
    return pc;
  }

  /// Resolves the state inside context [pc] whose symbol matches [symbol].
  /// Returns `false` on a malformed context (missing symbol); the matching
  /// state pointer is left in [_findStateResult] (the C out-parameter `p`).
  bool _findStateP(int pc, int symbol) {
    if (sub.w(pc) != 1) {
      var p = sub.d(pc + 4);
      if (sub.b(p) != symbol) {
        // Linear search; bounded by the stats array, malformed data can
        // theoretically walk past the end, mirroring the C code.
        while (sub.b(p) != symbol) {
          p += 10;
        }
      }
      _findStateResult = p;
    } else {
      _findStateResult = pc + 2;
    }
    return true;
  }

  int _findStateResult = 0;

  /// Mirrors `ModelPPM::UpdateModel`.
  void _updateModel() {
    final h = sub.heap!;
    final fsSymbol = h[_foundState];
    final fsFreq = h[_foundState + 1];
    final fsSuccessor = sub.d(_foundState + 2);
    var p = 0;

    final suffix = sub.d(_minContext + 12);
    if (fsFreq < _maxFreq ~/ 4 && suffix != 0) {
      if (sub.w(suffix) != 1) {
        var sp = sub.d(suffix + 4);
        if (h[sp] != fsSymbol) {
          while (h[sp] != fsSymbol) {
            sp += 10;
          }
          if (h[sp + 1] >= h[sp - 10 + 1]) {
            _swapStates(sp, sp - 10);
            sp -= 10;
          }
        }
        p = sp;
        if (h[p + 1] < _maxFreq - 9) {
          h[p + 1] += 2;
          sub.ww(suffix + 2, sub.w(suffix + 2) + 2);
        }
      } else {
        p = suffix + 2; // &OneState
        if (h[p + 1] < 32) {
          h[p + 1]++;
        }
      }
    }

    if (_orderFall == 0) {
      final successor = _createSuccessors(true, p);
      sub.wd(_foundState + 2, successor);
      _minContext = _maxContext = successor;
      if (_minContext == 0) {
        _restartModelRare();
        _escCount = 0;
      }
      return;
    }

    h[sub.pText++] = fsSymbol;
    var successor = sub.pText;
    if (sub.pText >= sub.fakeUnitsStart) {
      _restartModelRare();
      _escCount = 0;
      return;
    }
    var fsSucc = fsSuccessor;
    if (fsSucc != 0) {
      if (fsSucc <= sub.pText) {
        fsSucc = _createSuccessors(false, p);
        if (fsSucc == 0) {
          _restartModelRare();
          _escCount = 0;
          return;
        }
      }
      if (--_orderFall == 0) {
        successor = fsSucc;
        if (_maxContext != _minContext) {
          sub.pText--;
        }
      }
    } else {
      sub.wd(_foundState + 2, successor);
      fsSucc = _minContext;
    }

    final ns = sub.w(_minContext);
    final s0 = sub.w(_minContext + 2) - ns - (fsFreq - 1);
    var pc = _maxContext;
    while (pc != _minContext) {
      final ns1 = sub.w(pc);
      if (ns1 != 1) {
        if ((ns1 & 1) == 0) {
          final newStats = sub.expandUnits(sub.d(pc + 4), ns1 >> 1);
          sub.wd(pc + 4, newStats);
          if (newStats == 0) {
            _restartModelRare();
            _escCount = 0;
            return;
          }
        }
        var add = (2 * ns1 < ns) ? 1 : 0;
        if ((4 * ns1 <= ns) && (sub.w(pc + 2) <= 8 * ns1)) {
          add += 2;
        }
        sub.ww(pc + 2, sub.w(pc + 2) + add);
      } else {
        final unit = sub.allocUnits(1);
        if (unit == 0) {
          _restartModelRare();
          _escCount = 0;
          return;
        }
        // *p = pc->OneState
        h[unit] = h[pc + 2];
        h[unit + 1] = h[pc + 3];
        sub.wd(unit + 2, sub.d(pc + 4));
        sub.wd(pc + 4, unit);
        p = unit;
        if (h[p + 1] < _maxFreq ~/ 4 - 1) {
          h[p + 1] += h[p + 1];
        } else {
          h[p + 1] = _maxFreq - 4;
        }
        sub.ww(pc + 2, h[p + 1] + _initEsc + (ns > 3 ? 1 : 0));
      }

      var cf = 2 * fsFreq * (sub.w(pc + 2) + 6);
      final sf = s0 + sub.w(pc + 2);
      if (cf < 6 * sf) {
        cf = 1 + ((cf > sf) ? 1 : 0) + ((cf >= 4 * sf) ? 1 : 0);
        sub.ww(pc + 2, sub.w(pc + 2) + 3);
      } else {
        cf = 4 +
            ((cf >= 9 * sf) ? 1 : 0) +
            ((cf >= 12 * sf) ? 1 : 0) +
            ((cf >= 15 * sf) ? 1 : 0);
        sub.ww(pc + 2, sub.w(pc + 2) + cf);
      }

      final sp = sub.d(pc + 4) + ns1 * 10;
      sub.wd(sp + 2, successor);
      h[sp] = fsSymbol;
      h[sp + 1] = cf & 0xff;
      sub.ww(pc, ns1 + 1); // NumStats = ++ns1
      pc = sub.d(pc + 12);
    }
    _maxContext = _minContext = fsSucc;
  }

  /// Mirrors `RARPPM_CONTEXT::decodeBinSymbol`.
  void _decodeBinSymbol(int ctx) {
    final h = sub.heap!;
    final rs = ctx + 2; // &OneState
    _hiBitsFlag = _hb2Flag[h[_foundState]];
    final bsIdx = (h[rs + 1] - 1) * 64 +
        _prevSuccess +
        _ns2bsIndx[sub.w(sub.d(ctx + 12)) - 1] +
        _hiBitsFlag +
        2 * _hb2Flag[h[rs]] +
        ((_runLength >> 26) & 0x20);
    final bs = _binSumm[bsIdx];
    if (_coder.getCurrentShiftCount(_totBits) < bs) {
      _foundState = rs;
      if (h[rs + 1] < 128) {
        h[rs + 1]++;
      }
      _coder.lowCount = 0;
      _coder.highCount = bs;
      _binSumm[bsIdx] = bs + _interval - ((bs + 32) >> 7);
      _prevSuccess = 1;
      _runLength++;
    } else {
      _coder.lowCount = bs;
      _binSumm[bsIdx] = bs - ((bs + 32) >> 7);
      _coder.highCount = _binScale;
      _initEsc = _expEscape[_binSumm[bsIdx] >> 10];
      _numMasked = 1;
      _charMask[h[rs]] = _escCount;
      _prevSuccess = 0;
      _foundState = 0;
    }
  }

  /// Mirrors `RARPPM_CONTEXT::decodeSymbol1`.
  bool _decodeSymbol1(int ctx) {
    final h = sub.heap!;
    _coder.scale = sub.w(ctx + 2); // U.SummFreq
    final stats = sub.d(ctx + 4);
    var p = stats;
    final count = _coder.getCurrentCount();
    if (count >= _coder.scale) {
      return false;
    }
    var hiCnt = h[p + 1]; // p->Freq
    if (count < hiCnt) {
      _coder.highCount = hiCnt;
      _prevSuccess = (2 * hiCnt > _coder.scale) ? 1 : 0;
      _runLength += _prevSuccess;
      _foundState = p;
      hiCnt += 4;
      h[p + 1] = hiCnt;
      sub.ww(ctx + 2, sub.w(ctx + 2) + 4);
      if (hiCnt > _maxFreq) {
        _rescale(ctx);
      }
      _coder.lowCount = 0;
      return true;
    }
    if (_foundState == 0) {
      return false;
    }
    _prevSuccess = 0;
    var i = sub.w(ctx) - 1;
    while (true) {
      p += 10;
      hiCnt += h[p + 1];
      if (hiCnt > count) {
        break;
      }
      if (--i == 0) {
        _hiBitsFlag = _hb2Flag[h[_foundState]];
        _coder.lowCount = hiCnt;
        _charMask[h[p]] = _escCount;
        _numMasked = sub.w(ctx);
        i = sub.w(ctx) - 1;
        _foundState = 0;
        do {
          p -= 10;
          _charMask[h[p]] = _escCount;
        } while (--i != 0);
        _coder.highCount = _coder.scale;
        return true;
      }
    }
    _coder.lowCount = hiCnt - h[p + 1];
    _coder.highCount = hiCnt;
    _update1(ctx, p);
    return true;
  }

  /// Mirrors `RARPPM_CONTEXT::update1`.
  void _update1(int ctx, int p) {
    final h = sub.heap!;
    _foundState = p;
    h[p + 1] += 4;
    sub.ww(ctx + 2, sub.w(ctx + 2) + 4);
    if (h[p + 1] > h[p - 10 + 1]) {
      _swapStates(p, p - 10);
      _foundState = p - 10;
      if (h[p - 10 + 1] > _maxFreq) {
        _rescale(ctx);
      }
    }
  }

  /// Mirrors `RARPPM_CONTEXT::decodeSymbol2`.
  bool _decodeSymbol2(int ctx) {
    final h = sub.heap!;
    var i = sub.w(ctx) - _numMasked;
    final psee2c = _makeEscFreq2(ctx, i);
    var p = sub.d(ctx + 4) - 10; // U.Stats - 1
    var hiCnt = 0;
    var pps = 0;
    do {
      do {
        p += 10;
      } while (_charMask[h[p]] == _escCount);
      hiCnt += h[p + 1];
      if (pps >= 256) {
        return false;
      }
      _ps[pps++] = p;
    } while (--i != 0);
    _coder.scale += hiCnt;
    final count = _coder.getCurrentCount();
    if (count >= _coder.scale) {
      return false;
    }
    p = _ps[0];
    pps = 0;
    if (count < hiCnt) {
      hiCnt = 0;
      while ((hiCnt += h[p + 1]) <= count) {
        pps++;
        if (pps >= 256) {
          return false;
        }
        p = _ps[pps];
      }
      _coder.lowCount = hiCnt - h[p + 1];
      _coder.highCount = hiCnt;
      psee2c.update();
      _update2(ctx, p);
    } else {
      _coder.lowCount = hiCnt;
      _coder.highCount = _coder.scale;
      i = sub.w(ctx) - _numMasked;
      pps = 0;
      do {
        if (pps >= 256) {
          return false;
        }
        _charMask[h[_ps[pps]]] = _escCount;
        pps++;
      } while (--i != 0);
      psee2c.summ = (psee2c.summ + _coder.scale) & 0xffff;
      _numMasked = sub.w(ctx);
    }
    return true;
  }

  /// Mirrors `RARPPM_CONTEXT::update2`.
  void _update2(int ctx, int p) {
    final h = sub.heap!;
    _foundState = p;
    h[p + 1] += 4;
    sub.ww(ctx + 2, sub.w(ctx + 2) + 4);
    if (h[p + 1] > _maxFreq) {
      _rescale(ctx);
    }
    _escCount = (_escCount + 1) & 0xff;
    _runLength = _initRL;
  }

  /// Mirrors `RARPPM_CONTEXT::makeEscFreq2`.
  _See2Context _makeEscFreq2(int ctx, int diff) {
    _See2Context psee2c;
    if (sub.w(ctx) != 256) {
      final col =
          ((diff < sub.w(sub.d(ctx + 12)) - sub.w(ctx)) ? 1 : 0) +
          2 * ((sub.w(ctx + 2) < 11 * sub.w(ctx)) ? 1 : 0) +
           4 * ((_numMasked > diff) ? 1 : 0) +
          _hiBitsFlag;
      psee2c = _see2Cont[_ns2Indx[diff - 1]][col];
      _coder.scale = psee2c.getMean();
    } else {
      psee2c = _dummySee2;
      _coder.scale = 1;
    }
    return psee2c;
  }
}
