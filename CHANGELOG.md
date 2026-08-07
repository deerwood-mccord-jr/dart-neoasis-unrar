## 0.2.0

- RAR 3.x VM standard filters ported from `rarvm.cpp`/`unpack30.cpp`:
  E8/E8E9, ITANIUM, DELTA, RGB and AUDIO now decode on the RAR 2.9/3.x path
  (`lib/src/rarvm.dart`, wired into `unpack4.dart`).
- VM bytecode matching none of the six standard filters throws
  `UnsupportedFilterException` instead of silently truncating output.
- New test fixtures and coverage: 5 live RAR4 filter archives
  (E8E9, Delta, RGB, Audio, chained E8E9+Delta) extract byte-identical to
  the C library; `rarvm_test.dart` unit tests for `prepare`/`readData`.

## 0.1.0

- Project scaffold.
- Core foundation ported from the RARLAB UnRAR C source (7.2.3):
  CRC32 / Checksum14, raw endian readers, bit input, raw reader + vint,
  RAR4 unicode name decoder, archive signature detection, and RAR 4.x /
  RAR 5.0 block + main + file header parsing (entry listing).
- Unit tests for the ported primitives and header parsing.
- Example CLI that lists archive entries.
