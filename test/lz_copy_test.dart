import 'dart:typed_data';

import 'package:neoasis_unrar/src/lz_copy.dart';
import 'package:test/test.dart';

void main() {
  group('copyLzMatch', () {
    test('fills a distance-one repetition', () {
      final window = Uint8List(64)..[9] = 0x5a;
      final end = _copy(window, destination: 10, length: 20, distance: 1);

      expect(end, 30);
      expect(window.sublist(10, 30), everyElement(0x5a));
    });

    test('copies a non-overlapping match once', () {
      final window = Uint8List(64)..setRange(0, 8, [1, 2, 3, 4, 5, 6, 7, 8]);
      final end = _copy(window, destination: 16, length: 8, distance: 16);

      expect(end, 24);
      expect(window.sublist(16, 24), [1, 2, 3, 4, 5, 6, 7, 8]);
    });

    test('replicates overlapping non-power-of-two patterns', () {
      final window = Uint8List(64)..setRange(7, 10, [1, 2, 3]);
      final end = _copy(window, destination: 10, length: 17, distance: 3);

      expect(end, 27);
      expect(window.sublist(10, 27),
          [1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2]);
    });

    test('preserves replication across the circular boundary', () {
      final window = Uint8List(16)
        ..[12] = 7
        ..[13] = 8
        ..[14] = 9;
      final end = _copy(window,
          destination: 15,
          length: 8,
          distance: 3,
          firstWindowDone: true,
          endMargin: 8);

      expect(end, 7);
      expect([window[15], ...window.sublist(0, 7)], [7, 8, 9, 7, 8, 9, 7, 8]);
    });

    test('zero-fills invalid pre-window distances', () {
      final window = Uint8List(32)..fillRange(0, 32, 0xff);
      final end = _copy(window,
          destination: 2, length: 6, distance: 8, firstWindowDone: false);

      expect(end, 8);
      expect(window.sublist(2, 8), everyElement(0));
    });
  });
}

int _copy(
  Uint8List window, {
  required int destination,
  required int length,
  required int distance,
  bool firstWindowDone = true,
  int endMargin = 1,
}) =>
    copyLzMatch(
      window: window,
      destination: destination,
      length: length,
      distance: distance,
      windowSize: window.length,
      firstWindowDone: firstWindowDone,
      endMargin: endMargin,
    );
