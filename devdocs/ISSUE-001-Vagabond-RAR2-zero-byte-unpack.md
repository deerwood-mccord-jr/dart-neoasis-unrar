# ISSUE-001: Vagabond archive — RAR 2.x (unpVer 20) always unpacked to zero bytes

| | |
|---|---|
| Status | **Fixed** (2026-08-28) |
| Date | 2026-08-28 |
| Reported by | Real-world production archive (`Vagabond Volume 01`, 81 MB RAR from ~2003) |
| Affected | `lib/src/unpack4.dart::_unpWriteBuf20` (RAR 2.x decompression path) |
| Related | `BENCH-001-dart_unrar_vs_neoasis_unrar.md` §6.1, `HANDOFF-001-optimization-of-the-port.md` |
| Verification | 248/248 byte-identical vs FFI reference; full test suite 160 green |

---

## tl;dr

Every compressed entry in a 2003-era RAR 1.5 archive extracted as **zero
bytes**. Symbol decoding ran to completion, but the final output flush was
silently suppressed by a guard that consulted a counter the RAR 2.x loop had
already driven to `-1`. The output write path was the bug, not the decoder.

## Archive under test

- `Vagabond Volume 01 (Manga-Sketchbook).rar` — 81 MB, on the NAS at
  `/Volumes/NeoasysData4TB/Vagabond/…`
- Format: RAR 1.5 headers (`rarFmt15`), 260 entries (248 files / 12 dirs),
  70.8 MiB unpacked
- All compressed entries: method 3 (`NONE_COMPRESSED`), `unpVer=20`
  (RAR 2.0 decompressor), `windowSize=1048576` (1 MiB — the largest window
  RAR 2.x supports)

## Symptoms

1. Prior to the header fix, the archive refused to open at all:
   `UnrarHeaderException: Main archive header is corrupt`. Root cause was a
   separate issue — the main header carries a legacy in-header comment
   (`MHD_COMMENT = 0x0002`), and the port CRC'd 284 bytes of header (with
   comment) while RARLAB computes the CRC over only the fixed fields. Manual
   `crc16` over the fixed 11 bytes reproduced the stored `0x7d53` exactly.
   Fixed in `_readHeader15` (`archive_reader.dart`) by mirroring
   `arcread.cpp:203-221` + `GetCRC15`.
2. After (1), listing worked (260 entries) but extraction of every compressed
   file failed deterministically:

   ```
   [0] m=3 ver=20 win=1048576 unp=339230 pack=338498 :: FAIL
       ...035.jpg :: UnrarException: CRC32 mismatch for compressed entry
       (expected 1324576674, got 0)
   ```

   All four stored (`m=0`) entries extracted fine. Failures spanned the very
   first compressed entry onward, ruling out block-position drift.

## Root cause

`Unpack20`'s loop is bounded by `DestUnpSize`: every emitted symbol
(literal +1, back-reference +Length) decrements it, and the loop exits when it
goes negative — meaning *all `unpSize` output positions have already been
produced into the window*. The final `UnpWriteBuf20()` then drains
`[WrPtr, UnpPtr)` to the output.

The Dart port routed that drain through `_unpWriteData`, which begins with:

```dart
if (_writtenFileSize >= _destUnpSize) return; // gate
```

At the final flush `_destUnpSize == -1`, so `0 >= -1` is true and **the entire
flush was suppressed**. The decoder had done all the work; the output was
thrown away.

Why v29/v5 were never affected: their loops end on EOF/table-stream markers
with `DestUnpSize` still positive, so the gate legitimately passes at the
final flush. The RAR 2.x path has no such marker — it just runs out of
symbols. The C reference has no gate at all here:

- `unpack20.cpp::UnpWriteBuf20` targets `UnpIO->UnpWrite` directly.
- The gated `UnpWriteData` (`unpack50.cpp:538`) is only used by the v30/v50
  `UnpWriteArea` drains.

## Fix

`unpack4.dart::_unpWriteBuf20` now writes the window span directly to the
output `BytesBuilder`, capped only by the *original* destination size
(`_totalUnpSize` snapshot taken in `unpack4()`), preserving solid-stream and
malformed-stream overrun protection without consulting the exhausted
`_destUnpSize`:

```dart
var writeSize = _unpPtr < _wrPtr
    ? (_maxWinSize - _wrPtr) + _unpPtr
    : (_unpPtr - _wrPtr);
final leftToWrite = _totalUnpSize - _writtenFileSize;
if (writeSize > leftToWrite) writeSize = leftToWrite;
// ... add window[wrPtr..unpPtr) (with wrap) to _output, then _wrPtr = _unpPtr
```

### Related regression caught by the test suite

The comment fix (A) originally read a fixed
`SIZEOF_MAINHEAD3 - SIZEOF_SHORTBLOCKHEAD = 6` bytes for any
`MHD_COMMENT` main header. The synthetic `rar4_comment.rar` fixture flags a
comment but stores none: its header is only 7 bytes and its stored head CRC
(`0x334e`) covers just the 5 base fields (verified: `crc15([2:7]) == 0x334e`).
Reading 6 bytes past the end built a 13-byte buffer whose CRC (`0x1e1f`)
mismatched. The reference unrar also rejects this fixture (soft `BrokenHeader`
→ RARX error 12), but the neoasis test expects lenient open.

Fix: read `min(fixed, headSize - 7)` for comment-bearing main/comment
headers. Real in-header comments always have `headSize >= 13` (the Vagabond
archive does), so the reference behavior is unchanged for well-formed
archives; degenerate comment-flagged headers validate against base fields
alone.

## Files changed

| File | Change |
|---|---|
| `lib/src/unpack4.dart` | `_unpWriteBuf20` ungated drain (this issue, bug 2); `_totalUnpSize` field |
| `lib/src/archive_reader.dart` | `_readHeader15` read-size clamp for `MHD_COMMENT` / `HEAD3_CMT` (regression) |
| `lib/src/header_constants.dart` | `sizofCommHead = 13` (from earlier comment-support work) |

## Verification

- `rar_benchmark/bin/xcheck.dart` (extract-all with both, SHA-256 compare):
  **248/248 byte-identical** vs FFI `dart_unrar` on the Vagabond archive.
- `rar_benchmark/bin/probe.dart` on the full 81 MB: `testArchive: true` in
  ~1.2 s.
- `dart test`: suite green (160 pass / 2 skip).
- Benchmarks on the same archive recorded in `BENCH-001` §6.1.

## Why this escaped the fake corpus

- The regression harnesses used RAR 5 (`bench_rar5.rar`) and RAR 3.x w/ VM
  filter (`rar4_vmfilter_rgb.rar`, `unpVer=29`) — neither exercises the
  RAR 2.x drain semantics.
- The bug only manifests at the *final* flush, i.e. when `unpSize < window`
  (drain deferred entirely to the end) — typical of small JPEGs inside a
  1 MiB window.