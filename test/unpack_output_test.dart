import 'dart:typed_data';

import 'package:neoasis_unrar/src/blake2s.dart';
import 'package:neoasis_unrar/src/crc.dart';
import 'package:neoasis_unrar/src/unpack_output.dart';
import 'package:test/test.dart';

void main() {
  group('UnpackOutput', () {
    final data = Uint8List.fromList(List<int>.generate(257, (i) => i));

    test('writes known-size output into one exact buffer', () {
      final output = UnpackOutput(expectedSize: data.length, collect: true);
      output.add(data, 0, 17);
      output.add(data, 17, data.length - 17);

      final result = output.finish();
      expect(result.bytes, data);
      expect(result.bytes!.length, data.length);
      expect(result.length, data.length);
      expect(result.crc32, crc32Of(data));
      expect(result.checksum14, checksum14(0, data));
    });

    test('caps emitted data at the known final size', () {
      final output = UnpackOutput(expectedSize: 10, collect: true);
      output.add(data);

      final result = output.finish();
      expect(result.bytes, data.sublist(0, 10));
      expect(result.crc32, crc32Of(data.sublist(0, 10)));
    });

    test('unknown-size collection grows without a sentinel allocation', () {
      final output = UnpackOutput(expectedSize: null, collect: true);
      output.add(data, 0, 100);
      output.add(data, 100);

      expect(output.finish().bytes, data);
    });

    test('discard mode hashes without retaining output', () {
      final output = UnpackOutput(
        expectedSize: data.length,
        collect: false,
        computeBlake2: true,
      );
      for (var offset = 0; offset < data.length; offset += 13) {
        final length = (offset + 13).clamp(0, data.length) - offset;
        output.add(data, offset, length);
      }

      final result = output.finish();
      expect(result.bytes, isNull);
      expect(result.length, data.length);
      expect(result.crc32, crc32Of(data));
      expect(result.blake2Digest, Blake2Sp.digest(data));
    });
  });
}
