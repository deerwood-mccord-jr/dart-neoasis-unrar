## 0.1.0

- Project scaffold.
- Core foundation ported from the RARLAB UnRAR C source (7.2.3):
  CRC32 / Checksum14, raw endian readers, bit input, raw reader + vint,
  RAR4 unicode name decoder, archive signature detection, and RAR 4.x /
  RAR 5.0 block + main + file header parsing (entry listing).
- Unit tests for the ported primitives and header parsing.
- Example CLI that lists archive entries.
