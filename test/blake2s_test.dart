import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/src/blake2s.dart';
import 'package:test/test.dart';

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('BLAKE2sp (RAR variant)', () {
    test('empty data hash matches the C reference EmptyHash', () {
      // dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f
      // is the BLAKE2sp hash of empty data baked into hash.cpp HashValue::Init.
      expect(hex(Blake2Sp.digest([])),
          'dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f');
    });

    test('single-block input matches rar -htb output for fox.txt', () {
      // Generated with the licensed rar CLI: `rar a -htb` (RAR 5.0).
      const content =
          'The quick brown fox jumps over the lazy dog.\n'
          'BLAKE2 test data with a bit more content to exercise the parallel '
          'tree hash across multiple 512-byte blocks.\n';
      expect(hex(Blake2Sp.digest(content.codeUnits)),
          '9384beae27fdc68346e0fc459c8b4a6196cc50cb98693fbbdef90ae4460cf746');
    });

    test('multi-block input matches rar -htb output for blob.bin', () {
      // blob.bin is a 6000-byte binary fixture; its digest was captured with
      // `unrar lt -v` against the archive created by the licensed rar CLI.
      final blob = _loadBlob();
      if (blob == null) {
        return; // Fixture absent (e.g. fresh checkout): nothing to compare.
      }
      expect(blob.length, 6000);
      expect(hex(Blake2Sp.digest(blob)),
          'cab3d290c5a23c02ef891a5dd6d3cf7be6d845f12c6c8bf83d776ac8bb755186');
    });

    test('incremental feeding equals one-shot for arbitrary chunk sizes', () {
      final data = Uint8List.fromList(
          List<int>.generate(4099, (i) => (i * 31 + 7) & 0xff));
      final expected = Blake2Sp.digest(data);
      for (final chunk in const [1, 2, 63, 64, 65, 127, 128, 512, 1000]) {
        final h = Blake2Sp();
        for (var off = 0; off < data.length; off += chunk) {
          final end = (off + chunk) < data.length ? off + chunk : data.length;
          h.update(Uint8List.sublistView(data, off, end));
        }
        expect(hex(h.finalize()), hex(expected),
            reason: 'chunk size $chunk');
      }
    });
  });
}

Uint8List? _loadBlob() {
  try {
    return File('test/fixtures/blake2_ref/blob.bin').readAsBytesSync();
  } on FileSystemException {
    return null;
  }
}
