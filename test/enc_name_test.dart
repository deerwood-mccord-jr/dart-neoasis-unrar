import 'package:neoasis_unrar/src/enc_name.dart';
import 'package:test/test.dart';

void main() {
  group('decodeEncodedName', () {
    test('decodes a mixed 2-bit flag stream', () {
      // "Rém": 'R' as case 0 (raw byte), é as case 2 (raw 16-bit),
      // 'm' as case 1 (single byte + shared high byte 0x00).
      // Flag groups are consumed MSB-first: 00 10 01 ...
      final name = [0x52, 0x00]; // base ASCII name "R\0"
      final enc = [
        0x00, // HighByte
        0x24, // flags: 00 (case 0) 10 (case 2) 01 (case 1)
        0x52, // case 0: 'R'
        0xE9, 0x00, // case 2: é (little-endian)
        0x6D, // case 1: 'm'
      ];
      expect(decodeEncodedName(name, enc), 'Rém');
    });

    test('case 3 copies characters from the base name', () {
      // First flag group is 11 (case 3): repeat with correction 0.
      final name = 'ABCD'.codeUnits.toList()..add(0);
      final enc = [
        0x00, // HighByte
        0xC0, // flags: 11 00 00 00
        0x82, // length: (0x7f & 0x82) + 2 = 4
        0x00, // correction
      ];
      expect(decodeEncodedName(name, enc), 'ABCD');
    });

    test('case 3 with correction shifts the base name', () {
      final name = 'hello'.codeUnits.toList()..add(0);
      final enc = [
        0x00, // HighByte
        0xC0, // flags: 11 00 00 00
        0x85, // length: (0x7f & 0x85) + 2 = 7
        0x01, // correction: shift each char by +1
      ];
      expect(decodeEncodedName(name, enc), 'ifmmp\u0001');
    });

    test('does not run past the base name buffer', () {
      final name = [0x41, 0x42, 0x43, 0x00]; // "ABC\0"
      final enc = [
        0x00, // HighByte
        0xF0, // flags: 11 11 00 00
        0x83, // length: (0x7f & 0x83) + 2 = 5
        0x00, // correction
      ];
      expect(decodeEncodedName(name, enc), 'ABC\u0000');
    });

    test('empty encoded data yields an empty name', () {
      expect(decodeEncodedName([0x41, 0x00], []), '');
    });
  });
}
