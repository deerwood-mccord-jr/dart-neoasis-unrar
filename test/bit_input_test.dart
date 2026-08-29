import 'dart:typed_data';

import 'package:neoasis_unrar/src/bit_input.dart';
import 'package:neoasis_unrar/src/raw_int.dart';
import 'package:test/test.dart';

void main() {
  group('BitInput', () {
    test('reads a single byte of bits', () {
      final bi = BitInput();
      bi.buffer[0] = 0xB2; // 0b10110010
      expect(bi.getbits(), 0xB200); // 0b1011001000000000
      bi.addbits(3);
      expect(bi.getbits(), 0x9000); // 0b1001000000000000
      bi.addbits(3);
      expect(bi.getbits(), 0x8000); // 0b1000000000000000
    });

    test('crosses byte boundaries', () {
      final bi = BitInput();
      bi.buffer[0] = 0xFF;
      bi.buffer[1] = 0xAA;
      bi.buffer[2] = 0x00;
      expect(bi.getbits(), 0xFFAA);
      bi.addbits(8);
      expect(bi.getbits(), 0xAA00);
      bi.addbits(8);
      expect(bi.getbits(), 0x0000);
    });

    test('getbits32 across four bytes', () {
      final bi = BitInput();
      bi.buffer[0] = 0x12;
      bi.buffer[1] = 0x34;
      bi.buffer[2] = 0x56;
      bi.buffer[3] = 0x78;
      bi.buffer[4] = 0x9A;
      expect(bi.getbits32(), 0x12345678);
      bi.addbits(4);
      expect(bi.getbits32(), 0x23456789);
    });

    test('getbits64 across eight bytes', () {
      final bi = BitInput();
      bi.buffer[0] = 0x12;
      bi.buffer[1] = 0x34;
      bi.buffer[2] = 0x56;
      bi.buffer[3] = 0x78;
      bi.buffer[4] = 0x9A;
      bi.buffer[5] = 0xBC;
      bi.buffer[6] = 0xDE;
      bi.buffer[7] = 0xF0;
      bi.buffer[8] = 0x11;
      expect(bi.getbits64(), 0x123456789ABCDEF0);
      bi.addbits(4);
      expect(bi.getbits64(), 0x23456789ABCDEF01);
    });

    test('overflow detection', () {
      final bi = BitInput();
      bi.initBitInput();
      bi.buffer[0] = 1;
      expect(bi.overflow(0x8000), isTrue);
      expect(bi.overflow(0x7FFF), isFalse);
    });

    test('padded input does not copy caller-owned storage', () {
      final storage = Uint8List(PaddedInput.paddingSize + 2)
        ..[0] = 0x12
        ..[1] = 0x34;
      final input = PaddedInput(storage, 2);
      final bi = BitInput.padded(input);

      expect(bi.getbits(), 0x1234);
      storage[0] = 0xab;
      expect(bi.getbits(), 0xab34);
    });

    test('padded input safely supports look-ahead at logical end', () {
      final input = PaddedInput.copyOf(Uint8List.fromList([0xff]));
      final bi = BitInput.padded(input)..addbits(8);

      expect(bi.getbits(), 0);
      expect(bi.getbits32(), 0);
      expect(bi.getbits64(), 0);
    });
  });

  group('rawGetBe4', () {
    test('big-endian 4 byte load', () {
      expect(rawGetBe4([0x12, 0x34, 0x56, 0x78], 0), 0x12345678);
    });
  });

  group('rawGet8', () {
    test('little-endian 8 byte load', () {
      expect(rawGet8([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0), 1);
      expect(rawGet8([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0),
          0xFFFFFFFFFFFFFFFF);
    });
  });

  group('power of two helpers', () {
    test('isPow2', () {
      expect(isPow2(1), isTrue);
      expect(isPow2(2), isTrue);
      expect(isPow2(3), isFalse);
      expect(isPow2(1024), isTrue);
    });

    test('getGreaterOrEqualPow2', () {
      expect(getGreaterOrEqualPow2(1), 1);
      expect(getGreaterOrEqualPow2(5), 8);
      expect(getGreaterOrEqualPow2(8), 8);
    });

    test('getLessOrEqualPow2', () {
      expect(getLessOrEqualPow2(1), 1);
      expect(getLessOrEqualPow2(5), 4);
      expect(getLessOrEqualPow2(8), 8);
    });
  });
}
