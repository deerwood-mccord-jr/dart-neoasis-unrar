import 'dart:typed_data';

import 'package:neoasis_unrar/src/bit_input.dart';
import 'package:neoasis_unrar/src/crc.dart';
import 'package:neoasis_unrar/src/rarvm.dart';
import 'package:test/test.dart';

// The 57-byte x86 E8/E8E9 filter program, captured verbatim from the
// compressed stream of test/fixtures/rar4_vmfilter_ls.rar (verified against
// the StdList entry {57, 0x3cd7e57e, VMSF_E8E9}).
final Uint8List _e8e9Code = Uint8List.fromList([
  for (var i = 0; i < _e8e9Hex.length; i += 2)
    int.parse(_e8e9Hex.substring(i, i + 2), radix: 16),
]);

const String _e8e9Hex =
    '841b0128111069808000000d13a101c689d280ac9762855cc905c92f8148c8aa98'
    '1895728881aac95b0020ab6a03355811a24821b01291f4b8';

void main() {
  group('RarVM.prepare', () {
    test('matches the six standard filters by length + CRC', () {
      expect(crc32(0xffffffff, _e8e9Code) ^ 0xffffffff, 0x3cd7e57e);
      expect(_e8e9Code.length, 57);
      final prg = VmPreparedProgram();
      RarVm().prepare(_e8e9Code, prg);
      expect(prg.type, VmStandardFilter.e8e9);
    });

    test('rejects code failing the XOR checksum', () {
      final code = Uint8List.fromList(_e8e9Code);
      code[0] ^= 0xff;
      final prg = VmPreparedProgram();
      RarVm().prepare(code, prg);
      expect(prg.type, VmStandardFilter.none,
          reason: 'XOR check fails, so the program must not be recognized');
    });

    test('rejects XOR-valid but unrecognized (custom) bytecode', () {
      // XOR-valid: first byte is the XOR of the rest, but the length+CRC do
      // not match any standard filter.
      final code = Uint8List(6)..setAll(1, [1, 2, 3, 4, 5]);
      code[0] = 1 ^ 2 ^ 3 ^ 4 ^ 5;
      final prg = VmPreparedProgram();
      RarVm().prepare(code, prg);
      expect(prg.type, VmStandardFilter.none,
          reason: 'custom VM programs are not executed');
    });
  });

  group('RarVM.readData', () {
    test('decodes the 6/8/14-bit variable-width forms', () {
      // Bit stream, MSB-first (padded to 5 bytes):
      //   00 0101                       -> 6 bits: value 0x5
      //   01 10101011                   -> 10 bits: value 0xab
      //   01 0000 00111111              -> 14 bits: 0xffffff00 | 0x3f
      final inp = BitInput.external(
          Uint8List.fromList([0x15, 0xAB, 0x40, 0xFC, 0x00]));
      final v1 = RarVm.readData(inp);
      expect(v1, 0x5);
      final v2 = RarVm.readData(inp);
      expect(v2, 0xab);
      final v3 = RarVm.readData(inp);
      expect(v3, 0xffffff00 | 0x3f);
    });
  });
}
