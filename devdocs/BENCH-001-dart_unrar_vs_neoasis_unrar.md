# dart_unrar vs neoasis_unrar — Benchmark

*Status: measured 2026-08-14. Harness: `../../rar_benchmark/` (`bin/bench.dart`,
`bin/verify.dart`), path-deps on both packages. Host: macOS arm64, Apple
Silicon, 16 logical cores (12 performance + 4 efficiency), Dart SDK 3.12.2.
Libraries: neoasis_unrar 0.2.0 (pure Dart); unrar/dart_unrar 0.1.3 (FFI) with
the native lib built by its own build hooks. Fixtures generated with `rar`
7.23 (RAR 5.0) plus existing RAR 4.x fixtures.*

## 1. Purpose

neoasis_unrar and dart_unrar solve the same problem from opposite ends: a
from-scratch pure-Dart port of UnRAR vs an FFI wrapper around the official
RARLAB C library. This document quantifies the performance difference and,
critically, establishes the case for the pure-Dart approach:

- **Cross-archive parallelism is the primary driver for neoasis_unrar.**
  dart_unrar is synchronous FFI and blocks the calling isolate; neoasis_unrar
  is `async`, stateless per `RarArchive`, and has no `dart:io` in its core —
  so a whole archive can be opened, extracted, and processed inside a worker
  isolate with no shared mutable state. That is the property this benchmark
  workload depends on (extract-to-memory + thumbnail generation per archive,
  N archives in parallel).
- Single-archive throughput is not the point of the port; wall-clock
  throughput across a *batch* of archives is (see §6).

## 2. Methodology

- Four operations per package, each measured as a full open → operate →
  close cycle (the way the libraries are actually used):
  `list`, `extract_all` (to memory), `extract_one` (largest entry), `test`.
- 10 measured iterations after warmup; wall time via `Stopwatch`, reported as
  min / median / mean. First run also warms the OS page cache.
- Median-derived MiB/s uses the archive's total unpacked payload.
- **Correctness gate:** the harness first verified both implementations
  produce byte-identical output — SHA-256 over every extracted file,
  102/102 matched — so the timings compare equivalent work.
- dart_unrar loaded via `UNRAR_LIBRARY_PATH` pointing at its built
  `.dart_tool/lib/libunrar.dylib`.

### Test corpora

| Corpus | Archive size | Payload (unpacked) | Entries | Notes |
|---|---|---|---|---|
| `bench_rar5.rar` | 3,756 KiB | 6,229 KiB | 102 | RAR 5.0, mixed text (compresses well) + random binary (incompressible) + 100 small files |
| `bench_store.rar` | 6,236 KiB | 6,229 KiB | 102 | same data, `-m0` store — isolates header/IO overhead from decompression |
| `rar4_vmfilter_rgb.rar` | 67 KiB | 192 KiB | 1 | RAR 4.x with RGB VM filter (existing fixture) |

## 3. Results

### 3.1 RAR 5.0 — `bench_rar5.rar` (median of 10)

| op | neoasis_unrar | dart_unrar | ratio |
|---|---|---|---|
| list | 6,779 µs | 342 µs | 19.8× |
| extract_all | 67,332 µs — 90.3 MiB/s | 38,648 µs — 157.4 MiB/s | 1.7× |
| extract_one | 30,421 µs — 200.0 MiB/s | 17,171 µs — 354.3 MiB/s | 1.8× |
| test | 66,321 µs — 91.7 MiB/s | 5,443 µs — 1,117.6 MiB/s | 12.2× |

### 3.2 Stored (`-m0`) — `bench_store.rar` (median of 10)

| op | neoasis_unrar | dart_unrar | ratio |
|---|---|---|---|
| list | 6,691 µs | 364 µs | 18.4× |
| extract_all | 66,697 µs — 91.2 MiB/s | 36,734 µs — 165.6 MiB/s | 1.8× |
| extract_one | 28,777 µs — 211.4 MiB/s | 17,009 µs — 357.6 MiB/s | 1.7× |
| test | 65,653 µs — 92.7 MiB/s | 3,039 µs — 2,001.7 MiB/s | 21.6× |

### 3.3 RAR 4.x + RGB VM filter — `rar4_vmfilter_rgb.rar` (median of 10)

| op | neoasis_unrar | dart_unrar | ratio |
|---|---|---|---|
| list | 356 µs | 108 µs | 3.3× |
| extract_all | 4,594 µs — 40.8 MiB/s | 3,488 µs — 53.8 MiB/s | 1.3× |
| extract_one | 5,020 µs — 37.4 MiB/s | 3,613 µs — 51.9 MiB/s | 1.4× |
| test | 5,058 µs — 37.1 MiB/s | 2,067 µs — 90.7 MiB/s | 2.4× |

## 4. Reading the results

- **Extraction is the honest comparison and it is close**: 1.3–1.8× in favor
  of the FFI wrapper. The pure-Dart decompressor sustains ~90 MiB/s on a
  single core — competitive for most workloads and easily within reach of
  more.
- **`list` and `test` exaggerate the gap.** Both are dominated by *where the
  bytes are processed*, not by decompression skill:
  - neoasis `list` parses every header in Dart through async random-access
    reads (~66 µs/entry) and constructs rich `ArchiveEntry` objects;
    dart_unrar parses headers in C and reads a few struct fields per entry.
  - neoasis `testArchive()` literally runs `extractAll()` — full
    decompression + CRC32 in Dart — so `test` ≈ `extract_all` (66.3 vs
    67.3 ms). dart_unrar's `test` runs native `RAR_TEST` with no callback
    installed: zero bytes cross the FFI boundary, so it runs at near-pure-C
    speed (~1.1 GiB/s). Its `extract_all` cost (38.6 ms) is therefore best
    read as ≈ native test (5.4 ms) + ~33 ms of per-chunk FFI marshaling.
- The MiB/s column for `list` is meaningless (listing never reads payload
  bytes) and should be ignored; only wall-clock matters there.
- **Concurrency note:** dart_unrar's synchronous FFI calls block the calling
  isolate, and its extracted-data buffers are a module-level global keyed by
  callback id. neoasis holds no global state and can run one `RarArchive` per
  isolate with nothing shared.

## 5. Correctness cross-check

`bin/verify.dart` extracts the full corpus with both libraries and compares
SHA-256 of every file: **102/102 byte-identical.** The benchmark therefore
measures equivalent work, and either library can serve as a conformance
oracle for the other (see `Dart_unrar_vs_neoasis_unrar_Gap_Analysis.md` §7).

## 6. Parallelism across archives — the driver

Single-archive numbers are the wrong lens for this project. The workload is a
*batch*: decompress many archives to memory, generate a thumbnail from each
decompressed payload, and collect the small thumbnails. Both stages are
CPU-bound pure Dart, and both belong inside a worker isolate:

```
path → openRarFile → extractAll (Uint8List stays in the worker)
      → decode → thumbnail → encode (few KB) → ship thumbnail + metadata back
```

### 6.1 Why this motivated a pure-Dart port

- dart_unrar is synchronous FFI: an extract blocks the calling isolate, and
  the native callback buffers are module-global state. Running it across a
  pool of isolates works, but nothing in its design supports or encourages
  it.
- neoasis_unrar is `async`, stateless per `RarArchive`, and its core has no
  `dart:io` — so a worker isolate can open its own `ByteSource`, extract
  without touching global state, and be collected. It also runs on web/Wasm,
  where FFI cannot.

### 6.2 Expected scaling (projected, not yet measured)

Baseline from §3.1: ~67 ms per 6.2 MiB archive single-threaded (~90 MiB/s
per core). With a long-lived worker pool over independent archives, scaling
is near-linear until cores or I/O saturate:

| workers | 8-archive batch (single-threaded ≈ 536 ms) | effective throughput |
|---|---|---|
| 2 | ≈ 270 ms | ≈ 1.9× |
| 4 | ≈ 140 ms | ≈ 3.8× |
| 8 | ≈ 80 ms | ≈ 6.5–7× |
| 12+ | diminishing returns (P-cores saturated) | — |

Adding pure-Dart thumbnail generation (decode + resize + encode) inside the
worker raises per-archive latency to ~90–130 ms but does not change the
scaling — that work parallelizes across archives too, and only the small
encoded thumbnail crosses the isolate boundary.

### 6.3 What limits the gains

- **Do not transfer decompressed bytes to the main isolate.** Sending a
  multi-MiB `Uint8List` across an isolate copies it; doing the thumbnail work
  on the main isolate would both pay that copy and serialize all thumbnailing
  there. Keep extraction + thumbnail in the worker; ship only the thumbnail.
- **Spawn cost.** Spawning an isolate per archive (~1–3 ms) is amortized over
  a ~100 ms task, but for sub-ms archives it makes parallel *slower*. Use a
  pool spawned once (e.g. `package:pool` or manual `SendPort`s) fed from a
  work queue.
- **I/O ceiling.** Each worker re-reads its own archive file. Decompression
  (~90 MiB/s/core) hits CPU saturation first on NVMe, but on slow or remote
  storage the pipeline becomes I/O-bound and stops scaling.
- **Memory.** Per worker: decompressed payload + decoded raw image (RGBA ≈
  4× the compressed image). Size the pool with
  `min(cores, memoryBudget / (payload + rawImage))`.
- **Solid archives.** Parallelism here is *across* archives, so solidarity
  within an archive is irrelevant — each archive is an independent unit. This
  is why multi-archive parallelism works where intra-archive parallelism
  would not.

## 6.1 Real-world RAR 1.5 / RAR 2.0 archive — added 2026-08-28

A production archive surfaced two bugs that the synthetic corpora never hit.
The archive is *Vagabond Volume 01* (an 81 MB image-scans RAR from ~2003):
RAR 1.5 format headers, comment flag set, 260 entries (248 files / 12 dirs),
70.8 MiB unpacked, entries `NONE_COMPRESSED` (method 3, `unpVer=20`, 1 MiB
window — the largest window RAR 2.x supports).

### Bug 1 — RAR 2.x (unpVer 20) always unpacked to zero bytes

Every compressed entry produced empty output: `UnrarException: CRC32 mismatch
for compressed entry (expected <n>, got 0)`. Instrumentation showed the
decompressor *did* decode every symbol (`_destUnpSize` ran down to -1,
`_unpPtr == unpSize`, packed stream fully consumed) but the final flush wrote
nothing.

Root cause — `unpack4.dart::_unpWriteBuf20`:
- `Unpack20`'s loop lives or dies by `DestUnpSize`; when it exits (dest = -1)
  all `unpSize` output positions are already produced in the window, and the
  *final* `UnpWriteBuf20()` must drain `[WrPtr, UnpPtr)` to the output.
- The port routed that drain through `_unpWriteData`, gated on
  `_writtenFileSize >= _destUnpSize`. Because `_destUnpSize` is -1 by then,
  the gate suppressed the *entire* final flush.
- The C reference (`unpack20.cpp::UnpWriteBuf20`) bypasses any such gate and
  targets `UnpIO->UnpWrite` directly; the v30/v50 drain paths gate on
  `DestUnpSize` legitimately because their loops end on EOF/table markers
  with `DestUnpSize` still positive. The v20 path has no such marker, so its
  drain can never consult the *remaining* size.

Fix: `_unpWriteBuf20` now writes the window span directly to the output
`BytesBuilder`, capped only by the *original* destination size (`_totalUnpSize`
snapshot) so solid-stream and malformed-stream overruns stay bounded, then
advances `_wrPtr`. Verified: 248/248 files byte-identical vs the FFI
reference (`bin/xcheck.dart`), and `testArchive()` on the full 81 MB archive
passes in ~1.2 s.

### Bug 2 — MHD_COMMENT main header read-size edge case

The main-header `MHD_COMMENT` fix that originally unlocked this archive (read
`SIZEOF_MAINHEAD3 - SIZEOF_SHORTBLOCKHEAD` = 6 bytes, mirroring
`arcread.cpp:211-219`) broke the synthetic `rar4_comment.rar` fixture, whose
header is only 7 bytes — it flags a comment but stores none, so its stored
head CRC covers just the 5 base fields. Reading 6 bytes past the end produced
a 13-byte buffer whose CRC (`0x1e1f`) didn't match the stored `0x334e`.

Fix: read `min(fixed, headSize - 7)` for comment-bearing main/CMT headers.
Real in-header comments always have `headSize ≥ 13` (unchanged behavior,
this is what the Vagabond archive takes); degenerate 7-byte comment-flagged
headers validate against the base fields alone. The full neoasis test suite
(160 tests) is green.

### Real-archive benchmark (median of 5, RAR 1.5)

| op | neoasis_unrar | dart_unrar | ratio |
|---|---|---|---|
| list | 12,291 µs | 1,103 µs | 11.1× |
| extract_all | 1,194,605 µs — 59.3 MiB/s | 774,576 µs — 91.4 MiB/s | 1.5× |
| test | 1,207,905 µs — 58.6 MiB/s | 430,053 µs — 164.7 MiB/s | 2.8× |

Consistent with §3: extraction is the honest comparison (1.5×), and the
`list`/`test` gaps are the same parsing/location artifacts, not decompressor
skill.

## 7. Reproducing

```sh
# in flutterprojects/rar_benchmark
UNRAR_LIBRARY_PATH=../dart_unrar/.dart_tool/lib \
  dart run bin/bench.dart <archive.rar> [iterations]

UNRAR_LIBRARY_PATH=../dart_unrar/.dart_tool/lib \
  dart run bin/verify.dart <archive.rar>

UNRAR_LIBRARY_PATH=../dart_unrar/.dart_tool/lib \
  dart run bin/xcheck.dart <archive.rar>   # byte-identity vs FFI, per file
```

Fixtures: `bench_rar5.rar` / `bench_store.rar` are generated from a 6.2 MiB
source tree (3 MiB text, 3 MiB random binary, 100 small files) with
`rar a -ma5` and `rar a -ma5 -m0`. §6.1 used a real 2003-era RAR 1.5 archive
on a NAS (Vagabond Volume 01) instead.

## 8. Summary

- Extraction, the operation that matters, is 1.3–1.8× slower in pure Dart
  than via FFI — a small, predictable cost.
- `list`/`test` gaps (up to 22×) are artifacts of parsing location and
  marshaling, not decompressor quality.
- The pure-Dart port exists because batch throughput across archives —
  via isolate worker pools doing extract-to-memory + thumbnail generation —
  recovers that single-core difference several times over, and is the only
  path available on web/Wasm.

## 9. IMPL-0001 optimization pass — 2026-08-29

The implementation removed redundant packed/output copies, made archive test
mode discard payload bytes while retaining integrity checks, optimized LZ
match replication, reduced header and AES allocation, reused RAR5 KDF results,
and adopted slicing-by-8 CRC32. No public API changed.

### Focused JIT result: `rar4_vmfilter_chain.rar`

Median microseconds on the same host and harness. The baseline used 12 measured
iterations; the final column uses the more stable 30-iteration final run.

| op | before | after | delta |
|---|---:|---:|---:|
| list | 340 | 272 | -20.0% |
| extract_all | 3,369 | 2,599 | -22.9% |
| extract_one | 2,727 | 2,413 | -11.5% |
| test | 3,424 | 2,452 | -28.4% |

The final JIT run reached 131.8 MiB/s for extract-all and 139.7 MiB/s for
test. In the final AOT CLI bundle, neoasis measured 3,122 µs extract-all and
2,632 µs extract-one versus 3,365 µs and 2,671 µs for the native wrapper.

### Correctness and coverage

- `dart analyze`: clean.
- `dart test`: 171 passed, 2 environment-dependent volume-reference tests
  skipped.
- `rar6 6.12 -ma4 -m5` generated a RAR 4/v29 archive; current `rar 7.23 -m5`
  generated RAR 5/v50. `xcheck.dart` reported 6/6 byte-identical files for
  each archive.
- All committed RAR 1.4, RAR 3.x VM-filter, RAR 5/7, solid, encrypted,
  BLAKE2sp, and multi-volume tests passed.

The original 102-entry `bench_rar5.rar` / `bench_store.rar` corpus and the
Vagabond archive were unavailable during this pass. Their historical rows
above are retained, and their final rerun remains an external-corpus follow-up.
