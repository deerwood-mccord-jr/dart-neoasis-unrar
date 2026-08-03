import 'package:neoasis_unrar/src/crc.dart';
import 'package:test/test.dart';

void main() {
  group('CRC32', () {
    // Reference vectors from the CRC32 self-test in crc.cpp.
    test('matches the test vectors in crc.cpp', () {
      final t1 = crc32(0xffffffff, 'testtesttest'.codeUnits, 0, 12) ^
          0xffffffff;
      expect(t1, 0x44608e84);

      final t2 = crc32(0, 'te\x80st'.codeUnits, 0, 5);
      expect(t2, 0xB2E5C5AE);

      final b = List<int>.generate(14, (i) => 0x7f + i);
      final t3 = crc32(0xffffffff, b, 0, 14) ^ 0xffffffff;
      expect(t3, 0x1DFA75DA);
    });

    test('chunked updates equal a single pass', () {
      final data = List<int>.generate(300, (i) => i);
      final whole = crc32(0xffffffff, data, 0, 300);
      var chained = 0xffffffff;
      for (var i = 0; i < 300; i += 17) {
        final end = (i + 17).clamp(0, 300);
        chained = crc32(chained, data, i, end - i);
      }
      expect(chained, whole);
    });

    test('empty data returns the seed', () {
      expect(crc32(0xffffffff, const []), 0xffffffff);
    });

    test('offset/length slicing', () {
      final data = <int>[1, 2, 3, 4, 5];
      expect(crc32(0, data, 1, 3), crc32(0, <int>[2, 3, 4]));
    });
  });

  group('Checksum14', () {
    test('matches reference behavior', () {
      expect(checksum14(0, <int>[0]), 0);
      // crc=(0+1)&0xffff=1; then (1<<1)|(1>>15)=2.
      expect(checksum14(0, <int>[1]), 2);
      // After [1]: 2. Then (2+2)=4; (4<<1)|(4>>15)=8.
      expect(checksum14(0, <int>[1, 2]), 8);
    });
  });
}
