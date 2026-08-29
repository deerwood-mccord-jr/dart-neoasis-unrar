# HANDOFF-001: Performance optimization of the pure-Dart port

| | |
|---|---|
| Status | **Work queue** — no item below is started |
| Date | 2026-08-28 |
| Owner | next engineer/agent working on neoasis_unrar throughput |
| Related | `BENCH-001-dart_unrar_vs_neoasis_unrar.md`, `ISSUE-001-Vagabond-RAR2-zero-byte-unpack.md`, `GAP-001-neoasis_unrar_vs_unrar_cplusplus.md` |
| Goal | Narrow the measured gaps: extraction 1.3–1.8×, list 11–20×, test 12–22× (vs FFI `dart_unrar`) |

---

## 0. Ground truth before optimizing

- **Correctness gate (must stay green):** `rar_benchmark/bin/verify.dart`
  (SHA-256, 102/102 byte-identical) and `bin/xcheck.dart` (per-file SHA-256
  vs FFI reference on the real Vagabond archive, 248/248). Run `dart test`
  (160 tests) — several are port-fidelity golden tests.
- **Measurement harness:** `rar_benchmark/bin/bench.dart <archive.rar> [iters]`
  → list / extract_all / extract_one / test, min·median·mean + MiB/s.
  Archives: `bench_rar5.rar` (RAR5), `bench_store.rar` (-m0), the
  `rar4_vmfilter_*.rar` fixtures, and the real Vagabond archive.
- **Record baseline BEFORE and AFTER each experiment** (host: macOS arm64,
  Apple Silicon, 16 logical cores, Dart SDK 3.12). Never report a change
  without both numbers.
- Profiling entry point: extract_one / extract_all on the Vagabond archive
  with `dart run --observe` (sample profiler) or `--profile`; `BitInput`,
  `_copyString`, `crc32`, and `_output.add` are the first-place suspects.

## 1. Where the time actually goes (per operation)

### extract_all — 1.3–1.8× (the honest comparison)

Decompression, CRC, and output assembly — all in pure Dart:

- **Bit decoding** (`lib/src/bit_input.dart:getbits`): 3 single-byte loads +
  shifts per 16-bit field; `decodeNumber` table walks per symbol. RAR4/5 are
  bit streams; this is the innermost loop.
- **Window copies** (`lib/src/unpack4.dart:_copyString`, same pattern in
  unpack5): byte-at-a-time with `WrapUp`/wrap-down arithmetic. A fast path
  exists for interior-of-window matches.
- **CRC32** (`lib/src/crc.dart`): byte-at-a-time single-table. The C
  reference is Slicing-by-16 — and on this ARM Mac actually uses the ARMv8
  hardware CRC instructions (`crc.cpp` `USE_NEON_CRC32`,
  `__builtin_aarch64_crc32x`). **Dart cannot beat silicon; treat the native
  CRC as an unreachable floor.**
- **Output assembly**: every unpacker accumulates into a `BytesBuilder`
  (`_output`) then `takeBytes()` — at least one full copy at the end, plus
  builder growth reallocations. For RAR2 the produced length is exactly
  `unpSize`; RAR5/RAR3 are ≤ `unpSize` (filters may shrink).

### test — 12–22× (mostly an API artifact)

neoasis `testArchive()` literally runs `extractAll()` — full decompress +
CRC *and* output materialization in Dart. dart_unrar's `test` runs native
`RAR_TEST` with no callback: zero bytes cross FFI, near-hardware speed. A
real "test-only" fast path (see P2-2) removes the unfair half without chasing
native CRC.

### list — 11–20×

Per-entry header parse via async random-access `Read`/`Seek` on a
`RandomAccessFile` (~66 µs/entry) plus building a rich `ArchiveEntry` per
entry. dart_unrar parses headers in C and marshals a few fields. No
decompression involved — syscall + allocation overhead dominates.

## 2. Work queue (ranked by expected gain ÷ risk)

### P1-1 · Output: preallocate exact buffer, drop BytesBuilder

Packers produce a *known* target length. Replace
`BytesBuilder + _output.add(...) + takeBytes()` with a
`Uint8List(unpSize)` written at a running offset and returned directly
(truncate if a filter shrank it). Removes builder growth copies and the final
full-size copy.

- Files: `unpack4.dart` (`_unpWriteData`, `_unpWriteBuf20`), `unpack5.dart`
  (`_unpWriteArea`/`_unpWriteData`), `unpack15.dart`.
- Risk: **low** — pure per-file allocation change; golden tests cover output.
- Watch: solid streams continue across files (WrPtr/UnpPtr live in the
  window, not the output builder); keep per-file counted writes.

### P1-2 · CRC: Slicing-by-16 for payload, byte path for headers

Payload CRC (`crc32Of`) runs over the whole output; headers are tiny — keep
the byte-at-a-time path there. Add a slicing-by-16 variant: 16 tables
(16 KB), process 16 bytes/iteration, byte loop for the ragged head/tail and
any non-16-aligned remainder. Preserve running-XOR `startCrc` semantics
(`crc32` is called incrementally in RAR5/V3 paths).

- Files: `lib/src/crc.dart` (+ table generator); call sites keep API.
- Expected: 2–4× on the CRC slice → roughly 5–15% of `extract_all` on
  CPU-heavy payloads. Do **not** expect the native gap to close (hardware CRC
  in C).
- Risk: **low-moderate** — pure function; golden vectors + xcheck verify.
- Note: 16 KB of tables must live behind one `final` (initialized lazily or
  const-generated) so it doesn't bloat per-isolate warm-up that matters for
  sub-ms archives.

### P1-3 · Between P1-1 and P1-2, measure which wins

Both are small, isolated, low-risk. Do P1-1 first (removes a whole copy step
per file), re-baseline, then P1-2. If combined gain on `extract_all` is <10%,
stop here — extraction parity is already acceptable per BENCH-001 §8.

### P2-1 · CopyString: chunked forward copy for overlapping matches

C's `CopyString` uses `UNPACK_COPY8` — 8-byte chunks copied in a loop, which
is what keeps RAR's forward-copy *replication* semantics for
`distance < length` matches. **Plain `memmove`/`Uint8List.setRange` is WRONG
here** (it copies original bytes, not the repeated pattern). Implement
`chunk = min(length, distance)` and loop `setRange(dest, src, chunk)` — each
inner `setRange` is native and overlap-safe once chunks don't overlap.

- Files: `_copyString` (`unpack4.dart`), equivalent in `unpack5.dart`.
- Expected: large part of the inner loop → biggest single decompressor win.
- Risk: **moderate-high** — subtlest port-fidelity trap in the codebase;
  must pass golden RAR2/RAR3/RAR5 fixtures **and** the 248-file xcheck.
  Keep the byte loop as the fallback; add a flag to toggle.

### P2-2 · Real `testArchive` fast path

Decompress and feed the window/CRC directly, never materializing output (or
materializing only a running CRC). Uses the P1-1 write path, skipped; v20/v29
drains go to a CRC accumulator instead of an output buffer.

- Expected: `test` time approaches `extract_all` (it cannot approach native
  `RAR_TEST` — that's FFI+hardware).
- This changes observable semantics? No: `test` returns bool + has no output.
  Keep it as the strict op it is today.
- Risk: low-moderate (isolated path), synergy with P1-1.

### P2-3 · list: sequential chunk read instead of per-header async reads

Headers are sequential in an archive; parse from a rolling in-memory buffer
(e.g. read 64 KiB chunks, replay `_BlockHeader` parsing from memory) instead
of `seek`+`read` per header (~66 µs × 260 headers on the Vagabond archive
= ~17 ms). The reader already isolates the source behind `ByteSource`
(`archive_reader.dart`); a buffered sequential source is the clean seam.

- Expected: list 2–5×, largest impact on the 11–20× `list` gap.
- Risk: moderate — `_source.seek`/`_rewind`/per-block random access exist
  today; must not break jumping to file data. Feature-flag the buffered
  source behind a `ByteSource` impl and gate on sequential-only paths.

### P3-1 · BitInput: batch loads

Read 4/8 bytes into one value once and extract bit fields, instead of 3
single-byte loads per `getbits`. Mirrors C's batched `getbits`/`getbits32`
semantics (`bit_input.dart` already exposes `getbits`/`getbits32`/`getbits64`).
Do only after P2-1 shows how much time remains in bit decoding.

### P3-2 · Wider parallelism (already documented, not port work)

BENCH-001 §6: worker-isolate pools, one archive per isolate,
extract-to-memory + thumbnail in the worker. The ARC case for the port; do
not re-litigate here.

## 3. Guardrails (these keep every experiment honest)

1. **Byte-identity is the contract.** `verify.dart` (102/102) and
   `xcheck.dart` (248/248) must pass after every micro-optimization. Do not
   trust a micro-benchmark that isn't backed by them.
2. **Overlapping-copy semantics (RAR) ≠ memmove.** Forward byte-copy
   *replicates* the shifted pattern for `distance < length`. Any vectorized
   copy must reproduce this (chunked loop), or it corrupts data C happily
   decodes.
3. **Running CRC state.** `crc32(startCrc, ...)` is incremental (RAR5/V3
   hash chaining). A slicing variant must chain identically.
4. **Port fidelity.** The C source is the spec
   (`dart_unrar/third_party/unrar/`). When a "bug" in Dart looks like C
   behavior, check C first — C is usually right (see ISSUE-001).
5. **Re-baseline on both corpus and the real archive.** Synthetic corpora
   never caught the ISSUE-001 bug; the real Vagabond archive must stay in the
   comparison set.
6. **Solid streams.** Per-file output length can differ from expectations;
   window state crosses file boundaries. Test with `dart_unrar/test_data/solid.rar`
   and the RAR4 solid fixtures before/after any output-copy change.

## 4. Definition of done

- `extract_all` on the Vagabond archive: measure and report Δ; stop if <10%.
- `list` on the same archive: 2×+.  (P2-3)
- `test`: within ~10–20% of `extract_all` (no more full materialization).
- All gates green; no golden test regressions; CHANGELOG/MILESTONES updated;
  results appended to `BENCH-001`.