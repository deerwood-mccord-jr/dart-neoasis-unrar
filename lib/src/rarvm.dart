/// RAR 3.x virtual machine, ported from `rarvm.hpp` / `rarvm.cpp`.
///
/// Only the six standard filters are implemented (x86 E8/E8E9, Itanium,
/// Delta, RGB and Audio). The full bytecode interpreter is not ported;
/// `RarVm.prepare` marks programs that do not match one of the standard
/// filter CRC signatures with [VmStandardFilter.none] so the caller can fail
/// loudly instead of silently emitting truncated data.
library;

import 'dart:typed_data';

import 'bit_input.dart';
import 'crc.dart';
import 'raw_int.dart';

/// `VM_MEMSIZE` from `rarvm.hpp`.
const int vmMemSize = 0x40000;

/// `VM_MEMMASK` from `rarvm.hpp`.
const int vmMemMask = vmMemSize - 1;

/// `MAX3_UNPACK_FILTERS` from `unpack.hpp`.
const int max3UnpackFilters = 8192;

/// `MAX3_UNPACK_CHANNELS` from `unpack.hpp`.
const int max3UnpackChannels = 1024;

/// `VM_StandardFilters` from `rarvm.hpp`.
enum VmStandardFilter { none, e8, e8e9, itanium, rgb, audio, delta }

/// Mirrors `VM_PreparedProgram` from `rarvm.hpp`.
class VmPreparedProgram {
  VmStandardFilter type = VmStandardFilter.none;
  final List<int> initR = List<int>.filled(7, 0);
  Uint8List? filteredData;
  int filteredDataSize = 0;
}

class _StandardFilter {
  const _StandardFilter(this.length, this.crc, this.type);

  final int length;
  final int crc;
  final VmStandardFilter type;
}

/// `StdList` from `RarVM::Prepare`.
const List<_StandardFilter> _stdFilters = [
  _StandardFilter(53, 0xad576887, VmStandardFilter.e8),
  _StandardFilter(57, 0x3cd7e57e, VmStandardFilter.e8e9),
  _StandardFilter(120, 0x3769893f, VmStandardFilter.itanium),
  _StandardFilter(29, 0x0e06077d, VmStandardFilter.delta),
  _StandardFilter(149, 0x1c2c5dc8, VmStandardFilter.rgb),
  _StandardFilter(216, 0xbc85e701, VmStandardFilter.audio),
];

/// Mirrors `RarVM` from `rarvm.cpp`.
class RarVm {
  final Uint8List _mem = Uint8List(vmMemSize + 4);
  final List<int> _r = List<int>.filled(8, 0);

  /// Mirrors `RarVM::Init`. The memory buffer is pre-allocated; it is shared
  /// across filters within a file and (like the C member `RarVM::Mem`) reused
  /// across files, so nothing is reset here.
  void init() {}

  /// Mirrors `RarVM::SetMemory`, copying [dataSize] bytes from [data] at
  /// [dataOffset] into the VM memory at [pos], bounded by `VM_MEMSIZE`.
  void setMemory(int pos, List<int> data, int dataOffset, int dataSize) {
    if (pos >= vmMemSize) {
      return;
    }
    var copySize = dataSize;
    if (pos + copySize > vmMemSize) {
      copySize = vmMemSize - pos;
    }
    if (copySize > 0) {
      _mem.setRange(pos, pos + copySize, data, dataOffset);
    }
  }

  /// Mirrors `RarVM::Prepare`. On success sets [prg].type to the matching
  /// standard filter. Programs that fail the XOR checksum, or pass it but do
  /// not match any standard filter signature, leave the type at
  /// [VmStandardFilter.none].
  void prepare(Uint8List code, VmPreparedProgram prg) {
    var xorSum = 0;
    for (var i = 1; i < code.length; i++) {
      xorSum ^= code[i];
    }
    if (xorSum != code[0]) {
      return;
    }
    final codeCrc = crc32(0xffffffff, code) ^ 0xffffffff;
    for (final f in _stdFilters) {
      if (f.crc == codeCrc && f.length == code.length) {
        prg.type = f.type;
        return;
      }
    }
  }

  /// Mirrors the static `RarVM::ReadData`, decoding a variable-width value
  /// (6/8/14/30-bit forms) from the bit stream.
  static int readData(BitInput inp) {
    var data = inp.getbits();
    switch (data & 0xc000) {
      case 0:
        inp.addbits(6);
        return (data >> 10) & 0xf;
      case 0x4000:
        if ((data & 0x3c00) == 0) {
          data = 0xffffff00 | ((data >> 2) & 0xff);
          inp.addbits(14);
        } else {
          data = (data >> 6) & 0xff;
          inp.addbits(10);
        }
        return data;
      case 0x8000:
        inp.addbits(2);
        data = inp.getbits();
        inp.addbits(16);
        return data;
      default:
        inp.addbits(2);
        data = (inp.getbits() << 16) & 0xFFFFFFFF;
        inp.addbits(16);
        data |= inp.getbits();
        inp.addbits(16);
        return data;
    }
  }

  /// Mirrors `RarVM::Execute`. Runs the standard filter for [prg].type and
  /// sets [VmPreparedProgram.filteredData] / `.filteredDataSize`.
  void execute(VmPreparedProgram prg) {
    _r.setRange(0, prg.initR.length, prg.initR);
    prg.filteredData = null;
    prg.filteredDataSize = 0;
    if (prg.type == VmStandardFilter.none) {
      return;
    }
    final success = _executeStandardFilter(prg.type);
    final blockSize = prg.initR[4] & vmMemMask;
    prg.filteredDataSize = blockSize;
    if (prg.type == VmStandardFilter.delta ||
        prg.type == VmStandardFilter.rgb ||
        prg.type == VmStandardFilter.audio) {
      prg.filteredData = (2 * blockSize > vmMemSize || !success)
          ? _mem
          : Uint8List.sublistView(_mem, blockSize, 2 * blockSize);
    } else {
      prg.filteredData = _mem;
    }
  }

  bool _executeStandardFilter(VmStandardFilter type) {
    switch (type) {
      case VmStandardFilter.e8:
      case VmStandardFilter.e8e9:
        return _executeE8(type);
      case VmStandardFilter.itanium:
        return _executeItanium();
      case VmStandardFilter.delta:
        return _executeDelta();
      case VmStandardFilter.rgb:
        return _executeRgb();
      case VmStandardFilter.audio:
        return _executeAudio();
      case VmStandardFilter.none:
        return true;
    }
  }

  bool _executeE8(VmStandardFilter type) {
    final data = _mem;
    final dataSize = _r[4];
    final fileOffset = _r[6];
    if (dataSize > vmMemSize || dataSize < 4) {
      return false;
    }
    const fileSize = 0x1000000;
    final cmpByte2 = type == VmStandardFilter.e8e9 ? 0xe9 : 0xe8;
    var pos = 0;
    var curPos = 0;
    while (curPos < dataSize - 4) {
      final curByte = data[pos];
      pos++;
      curPos++;
      if (curByte == 0xe8 || curByte == cmpByte2) {
        final offset = (curPos + fileOffset) & 0xFFFFFFFF;
        final addr = rawGet4(data, pos);
        if ((addr & 0x80000000) != 0) {
          if (((addr + offset) & 0x80000000) == 0) {
            _putLe4(data, pos, (addr + fileSize) & 0xFFFFFFFF);
          }
        } else {
          if (((addr - fileSize) & 0x80000000) != 0) {
            _putLe4(data, pos, (addr - offset) & 0xFFFFFFFF);
          }
        }
        pos += 4;
        curPos += 4;
      }
    }
    return true;
  }

  bool _executeItanium() {
    final data = _mem;
    final dataSize = _r[4];
    var fileOffset = _r[6];
    if (dataSize > vmMemSize || dataSize < 21) {
      return false;
    }
    var pos = 0;
    var curPos = 0;
    fileOffset >>= 4;
    const masks = [4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];
    while (curPos < dataSize - 21) {
      final byte = (data[pos] & 0x1f) - 0x10;
      if (byte >= 0) {
        final cmdMask = masks[byte];
        if (cmdMask != 0) {
          for (var i = 0; i <= 2; i++) {
            if ((cmdMask & (1 << i)) != 0) {
              final startPos = i * 41 + 5;
              final opType =
                  _filterItaniumGetBits(data, pos + startPos + 37, 4);
              if (opType == 5) {
                final offset =
                    _filterItaniumGetBits(data, pos + startPos + 13, 20);
                _filterItaniumSetBits(data, (offset - fileOffset) & 0xfffff,
                    pos + startPos + 13, 20);
              }
            }
          }
        }
      }
      pos += 16;
      curPos += 16;
      fileOffset++;
    }
    return true;
  }

  bool _executeDelta() {
    final dataSize = _r[4];
    final channels = _r[0];
    if (dataSize > vmMemSize ~/ 2 ||
        channels > max3UnpackChannels ||
        channels == 0) {
      return false;
    }
    var srcPos = 0;
    final border = dataSize * 2;
    for (var curChannel = 0; curChannel < channels; curChannel++) {
      var prevByte = 0;
      for (var destPos = dataSize + curChannel;
          destPos < border;
          destPos += channels) {
        prevByte = (prevByte - _mem[srcPos++]) & 0xff;
        _mem[destPos] = prevByte;
      }
    }
    return true;
  }

  bool _executeRgb() {
    final dataSize = _r[4];
    final width = (_r[0] - 3) & 0xFFFFFFFF;
    final posR = _r[1];
    if (dataSize > vmMemSize ~/ 2 ||
        dataSize < 3 ||
        width > dataSize ||
        posR > 2) {
      return false;
    }
    var srcPos = 0;
    for (var curChannel = 0; curChannel < 3; curChannel++) {
      var prevByte = 0;
      for (var i = curChannel; i < dataSize; i += 3) {
        var predicted = prevByte;
        if (i >= width + 3) {
          final upperIndex = dataSize + i - width;
          final upperByte = _mem[upperIndex];
          final upperLeftByte = _mem[upperIndex - 3];
          predicted = prevByte + upperByte - upperLeftByte;
          final pa = (predicted - prevByte).abs();
          final pb = (predicted - upperByte).abs();
          final pc = (predicted - upperLeftByte).abs();
          if (pa <= pb && pa <= pc) {
            predicted = prevByte;
          } else if (pb <= pc) {
            predicted = upperByte;
          } else {
            predicted = upperLeftByte;
          }
        }
        prevByte = (predicted - _mem[srcPos++]) & 0xff;
        _mem[dataSize + i] = prevByte;
      }
    }
    for (var i = posR, border = dataSize - 2; i < border; i += 3) {
      final g = _mem[dataSize + i + 1];
      _mem[dataSize + i] = (_mem[dataSize + i] + g) & 0xff;
      _mem[dataSize + i + 2] = (_mem[dataSize + i + 2] + g) & 0xff;
    }
    return true;
  }

  bool _executeAudio() {
    final dataSize = _r[4];
    final channels = _r[0];
    if (dataSize > vmMemSize ~/ 2 || channels > 128 || channels == 0) {
      return false;
    }
    var srcPos = 0;
    for (var curChannel = 0; curChannel < channels; curChannel++) {
      var prevByte = 0;
      var prevDelta = 0;
      final dif = List<int>.filled(7, 0);
      var d1 = 0;
      var d2 = 0;
      var d3 = 0;
      var k1 = 0;
      var k2 = 0;
      var k3 = 0;
      var byteCount = 0;
      for (var i = curChannel; i < dataSize; i += channels, byteCount++) {
        d3 = d2;
        d2 = ((prevDelta - d1) & 0xFFFFFFFF).toSigned(32);
        d1 = prevDelta.toSigned(32);

        final predicted32 =
            (8 * prevByte + k1 * d1 + k2 * d2 + k3 * d3) & 0xFFFFFFFF;
        var predicted = (predicted32 >> 3) & 0xff;
        final curByte = _mem[srcPos++];
        final outByte = (predicted - curByte) & 0xff;
        _mem[dataSize + i] = outByte;

        prevDelta = (outByte - prevByte).toSigned(8) & 0xFFFFFFFF;
        prevByte = outByte;

        final d = curByte.toSigned(8) << 3;
        dif[0] += d.abs();
        dif[1] += (d - d1).abs();
        dif[2] += (d + d1).abs();
        dif[3] += (d - d2).abs();
        dif[4] += (d + d2).abs();
        dif[5] += (d - d3).abs();
        dif[6] += (d + d3).abs();

        if ((byteCount & 0x1f) == 0) {
          var minDif = dif[0];
          var numMinDif = 0;
          dif[0] = 0;
          for (var j = 1; j < 7; j++) {
            if (dif[j] < minDif) {
              minDif = dif[j];
              numMinDif = j;
            }
            dif[j] = 0;
          }
          switch (numMinDif) {
            case 1:
              if (k1 >= -16) {
                k1--;
              }
              break;
            case 2:
              if (k1 < 16) {
                k1++;
              }
              break;
            case 3:
              if (k2 >= -16) {
                k2--;
              }
              break;
            case 4:
              if (k2 < 16) {
                k2++;
              }
              break;
            case 5:
              if (k3 >= -16) {
                k3--;
              }
              break;
            case 6:
              if (k3 < 16) {
                k3++;
              }
              break;
          }
        }
      }
    }
    return true;
  }

  /// Mirrors `RarVM::FilterItanium_GetBits`.
  int _filterItaniumGetBits(Uint8List data, int bitPos, int bitCount) {
    var inAddr = bitPos >> 3;
    final inBit = bitPos & 7;
    var bitField = data[inAddr++] |
        (data[inAddr++] << 8) |
        (data[inAddr++] << 16) |
        (data[inAddr] << 24);
    bitField >>= inBit;
    return bitField & (0xffffffff >> (32 - bitCount));
  }

  /// Mirrors `RarVM::FilterItanium_SetBits`.
  void _filterItaniumSetBits(
      Uint8List data, int bitField, int bitPos, int bitCount) {
    final inAddr = bitPos >> 3;
    final inBit = bitPos & 7;
    var andMask = (0xffffffff >> (32 - bitCount)) & 0xFFFFFFFF;
    andMask = (~((andMask << inBit) & 0xFFFFFFFF)) & 0xFFFFFFFF;
    var field = (bitField << inBit) & 0xFFFFFFFF;
    for (var i = 0; i < 4; i++) {
      data[inAddr + i] = (data[inAddr + i] & andMask) | field;
      andMask = ((andMask >> 8) | 0xff000000) & 0xFFFFFFFF;
      field = (field >> 8) & 0xFFFFFFFF;
    }
  }
}

void _putLe4(Uint8List data, int offset, int value) {
  data[offset] = value & 0xff;
  data[offset + 1] = (value >> 8) & 0xff;
  data[offset + 2] = (value >> 16) & 0xff;
  data[offset + 3] = (value >> 24) & 0xff;
}
