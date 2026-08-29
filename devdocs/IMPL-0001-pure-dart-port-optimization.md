# IMPL-0001: Optimize the pure-Dart UnRAR port

| | |
|---|---|
| Status | **Planned** — implementation not started |
| Date | 2026-08-29 |
| Owner | next engineer/agent working on `neoasis_unrar` throughput |
| Related | `HANDOFF-001-optimization-of-the-port.md`, `BENCH-001-dart_unrar_vs_neoasis_unrar.md`, `GAP-001-neoasis_unrar_vs_unrar_cplusplus.md` |
| Reference | `../dart_unrar/third_party/unrar/` |
| Goal | Reduce avoidable allocation, copying, hashing, and header-I/O overhead while preserving byte-identical behavior across RAR 1.4 through RAR 7.0 |

---

## 1. Outcome and success criteria

This plan optimizes the pure-Dart implementation in dependency order. It starts
with whole-buffer copies and boxed-byte allocations, then introduces the output
sink needed by both extraction and test mode, and only then changes inner-loop
decompression code.

The work is complete when all of the following are true:

1. `dart analyze` is clean and the full `dart test` suite passes.
2. `rar_benchmark/bin/verify.dart` reports byte-identical output for the full
   benchmark corpus.
3. `rar_benchmark/bin/xcheck.dart` reports byte-identical output for every file
   in the real Vagabond archive.
4. No benchmark regression greater than 3% is accepted without a documented
   workload-specific justification.
5. On the Vagabond archive:
   - `extract_all` improves by at least 10%, or the plan records that the
     remaining gap is dominated by unavoidable Dart-versus-hardware costs;
   - `list` improves by at least 2x;
   - `test` is within 10–20% of `extract_all`.
6. Peak retained memory during extraction does not increase. For known-size
   entries it should decrease because oversized `BytesBuilder` backing buffers
   and boxed packed-byte lists are removed.
7. Results and rejected experiments are appended to
   `BENCH-001-dart_unrar_vs_neoasis_unrar.md`.

## 2. Non-goals

- No FFI, native extension, platform channel, or `dart:io` dependency in the
  core library.
- No intra-archive parallel decompression. Solid-stream ordering remains
  sequential.
- No attempt to match ARMv8 hardware CRC throughput used by native UnRAR.
- No public API break solely for performance. Internal APIs may change.
- No decoder rewrite until profiling after the allocation and output phases.

## 3. Ground truth and measurement protocol

### 3.1 Correctness gates

Run these after every phase and after every inner-loop experiment:

```sh
cd /Users/dmccordjr/DevProjects/flutterprojects/neoasis_unrar
dart analyze
dart test

cd /Users/dmccordjr/DevProjects/flutterprojects/rar_benchmark
UNRAR_LIBRARY_PATH=../dart_unrar/.dart_tool/lib/libunrar.dylib \
  dart run bin/verify.dart <benchmark-archive.rar>
UNRAR_LIBRARY_PATH=../dart_unrar/.dart_tool/lib/libunrar.dylib \
  dart run bin/xcheck.dart <vagabond-archive.rar>
```

Required focused fixtures:

- RAR 1.4/1.5: the applicable legacy corpus and a genuinely compressed
  `unpVer` 10/13/15 fixture;
- RAR 2.x: the Vagabond archive and `unpVer` 20/26 fixtures;
- RAR 3.x: all `rar4_vmfilter_*.rar` fixtures;
- RAR 5.0/7.0: `basic_rar5.rar`, `solid.rar`, encrypted fixtures, and split
  volumes;
- stored data: `bench_store.rar` and encrypted stored fixtures;
- solid data: RAR 4 and RAR 5 solid fixtures.

### 3.2 Benchmark matrix

Measure before and after each phase, in the same process mode and on the same
host:

| Corpus | Required operations | Purpose |
|---|---|---|
| `bench_rar5.rar` | list, extract_all, extract_one, test | Mixed RAR 5 workload |
| `bench_store.rar` | list, extract_all, extract_one, test | Header, I/O, copy, and CRC costs |
| `rar4_vmfilter_chain.rar` | extract_all, extract_one, test | RAR 3 VM-filter write path |
| `rar4_vmfilter_rgb.rar` | extract_all, test | CPU-heavy filter path |
| RAR 4 solid fixture | extract_all, extract_one | Cross-file window state |
| Vagabond archive | list, extract_all, test | Real RAR 2 workload and acceptance corpus |
| encrypted RAR 5 fixture | extract_all, test | KDF and AES costs |

Use at least 3 warmups and 10 measured iterations for normal corpora, and 5
measured iterations for the real archive. Record minimum, median, mean,
standard deviation, MiB/s, archive size, payload size, Dart SDK, build mode,
and git revision.

Do not combine unrelated optimizations in one measurement. Each experiment
must have a before number, an after number, correctness results, and a keep or
revert decision.

### 3.3 Profiling checkpoints

Profile after phases 2, 4, and 6. Use `extract_one`, `extract_all`, `list`, and
`test` independently. Capture allocation and CPU samples where possible.

The decision to proceed to CRC slicing or a bit reservoir must be based on the
post-copy profile, not the original baseline.

## 4. Architecture used by the optimized paths

The implementation should converge on two internal seams:

1. A packed-input buffer that distinguishes allocated capacity from logical
   compressed length. It includes safe zero padding without copying the packed
   stream again.
2. An unpack-output sink that accepts byte ranges, updates integrity state, and
   optionally collects output.

```text
ByteSource
  -> preallocated padded packed buffer
  -> BitInput (logical length + padded capacity)
  -> RAR 1.5 / 2.x / 3.x / 5.x decoder
  -> UnpackOutputSink
       -> extraction: hash + write into exact output buffer
       -> test:       hash + discard
       -> unknown size: hash + bounded growable collector
```

This mirrors native UnRAR's `ComprDataIO::UnpWrite`: the decoder emits chunks,
the write layer maintains hashes, and test mode suppresses destination output
without suppressing decompression or verification.

## 5. Implementation phases

### Phase 0 — Freeze baselines and add performance-sensitive correctness tests

**Purpose:** make all later experiments attributable and safe.

Tasks:

- Record the complete benchmark matrix before editing performance code.
- Add focused unit tests for packed reads that return multiple short chunks.
- Add `BitInput` end-of-buffer tests for 16-, 32-, and 64-bit over-read padding.
- Add output tests covering exact size, zero size, unknown size, truncated
  streams, filtered output, and solid continuation.
- Add direct match-copy tests for:
  - `distance == 1`;
  - `distance < length` with non-power-of-two patterns;
  - `distance == length`;
  - `distance > length`;
  - source and destination crossing the circular-window boundary;
  - invalid pre-window and over-window distances.
- Add incremental CRC vectors with varied chunk boundaries and non-default
  starting CRC state.
- Acquire or construct a genuinely compressed RAR 1.4/1.5 fixture before
  changing `unpack15.dart`; current legacy coverage must not be assumed to
  exercise that decoder fully.

Exit gate: baseline recorded and all new tests pass on unoptimized code.

### Phase 1 — Remove boxed packed-input accumulation

**Files:**

- `lib/src/unpacker.dart`
- `lib/src/archive_reader.dart`
- `lib/src/bit_input.dart`
- `lib/src/byte_source.dart`
- `lib/io.dart`

**C reference:** `getbits.hpp`, `unpack.cpp`, and `RawRead`/`UnpRead` paths.

Tasks:

1. Replace `_readUpTo` and `_readExact` implementations based on growable
   `List<int>` plus `addAll` with preallocated `Uint8List` buffers and a running
   write offset.
2. Return an exact view when EOF produces fewer bytes than requested.
3. Add an internal packed-buffer representation containing:
   - the `Uint8List` storage;
   - logical compressed length;
   - guaranteed zero-padding length.
4. Change `BitInput.external` so it can consume already-padded storage without
   allocating and copying the entire stream. Preserve a safe copying factory
   for callers that do not provide padded storage.
5. Let the unpacker read directly into a `packSize + padding` allocation for
   unencrypted compressed data.
6. For encrypted data, avoid an unpadded intermediate after decryption. The
   decryptor should return or fill padded typed storage.
7. Change `MemoryByteSource.read` to use a typed sublist view where ownership
   rules permit; document that the returned bytes must be treated as read-only.

Guardrails:

- The bit reader must never expose padding as compressed data.
- Short reads must preserve their current EOF behavior.
- Decryption must not include padding bytes that were not present in the
  ciphertext.
- Do not pass a mutable view to code that can outlive or overwrite its backing
  buffer.

Expected result: lower allocation volume and fewer full packed-stream copies,
especially for compressed files and many-entry archives.

Exit gate: correctness matrix green and no benchmark regression over 3%.

### Phase 2 — Replace output builders with sinks and exact buffers

**Files:**

- `lib/src/unpack4.dart`
- `lib/src/unpack5.dart`
- `lib/src/unpack15.dart`
- `lib/src/unpacker.dart`
- new internal sink file if it keeps responsibilities clear

**C reference:** `rdwrfn.cpp::ComprDataIO::UnpWrite`, `unpack20.cpp`,
`unpack30.cpp::UnpWriteBuf30`, and `unpack50.cpp::UnpWriteData`.

Tasks:

1. Introduce an internal `UnpackOutputSink` with a range-oriented operation,
   such as `add(Uint8List data, int offset, int length)`.
2. Implement a collecting sink that preallocates exactly `unpSize` when the
   size is known and writes with `setRange` at a running offset.
3. Implement a bounded growable collector for `unknownUnpSize`. Do not attempt
   to allocate the `int64Ndf` sentinel.
4. Remove `data.sublist(...)` allocations from `_unpWriteData`; pass source
   ranges directly to the sink.
5. Convert RAR 1.5 `_out` from growable `List<int>` to the shared sink. Review
   its final flush separately because the legacy loop mutates the destination
   counter during decoding.
6. Preserve RAR 2.x's special final-drain behavior: `_unpWriteBuf20` is capped
   against the original file size, not the decremented remaining-size counter.
7. Preserve RAR 3 VM-filter output sizes. `FilteredDataSize`, rather than input
   `BlockLength`, advances collected output for filters capable of changing
   size.
8. For known-size valid files, return the allocated output buffer directly.
   For malformed or short output, retain existing error and CRC behavior.

Guardrails:

- `unpSize` is the final output size for known-size entries, including filtered
  files, but filter emissions still use their actual emitted lengths.
- Window state is not output state; solid dictionaries must continue across
  per-file sink replacement.
- Unknown-size entries require a growable path.
- Do not use `BytesBuilder(copy: false)` with views into the mutable sliding
  window.

Expected result: removal of growth reallocations, intermediate sublists, boxed
RAR 1.5 output, and oversized retained backing buffers.

Exit gate: all golden fixtures and real-archive cross-checks pass; record peak
memory and extraction deltas.

### Phase 3 — Hash during output and add real test mode

**Files:**

- output sink implementation
- `lib/src/unpacker.dart`
- `lib/src/archive_reader.dart`
- `lib/src/crc.dart`
- `lib/src/blake2s.dart`

**C reference:** `rdwrfn.cpp::ComprDataIO::UnpWrite` and `extract.cpp` test-mode
setup.

Tasks:

1. Add incremental integrity state to the sink:
   - CRC32 with native-compatible running-XOR semantics;
   - Checksum14 for RAR 1.4;
   - BLAKE2sp only when requested by the entry;
   - HMAC conversion after the underlying CRC/BLAKE2 result is finalized.
2. Remove post-decompression full-buffer CRC and BLAKE2 rescans where the sink
   has already calculated the result.
3. Add a discard sink for `testArchive()` that updates integrity state without
   allocating per-file output.
4. Route stored entries through the same integrity sink so test mode can read,
   hash, and discard them without returning a payload.
5. Keep all filter execution active in test mode; hash the post-filter bytes.
6. Keep solid window and old-distance state active when output is discarded.
7. Preserve redirect validation and multi-volume behavior. A redirect may still
   require source-entry processing even though no final bytes are retained.
8. Make `testArchive()` invoke the verification path directly instead of
   calling `extractAll()` with an empty callback.

Guardrails:

- Header CRC and payload CRC APIs must remain semantically distinct.
- Hash chunk boundaries must not affect results.
- Encrypted CRC32-MAC and BLAKE2-MAC must reuse the actual plaintext hash.
- `testArchive()` remains strict: unsupported algorithms and corrupt entries
  fail exactly as extraction does.

Expected result: `test` approaches `extract_all`, while extraction avoids a
second cold traversal over every completed output buffer.

Exit gate: `test` is within 10–20% of `extract_all` on the real archive and all
encrypted/hash fixtures pass.

### Phase 4 — Optimize overlapping LZ match copies

**Files:**

- `lib/src/unpack4.dart`
- `lib/src/unpack5.dart`
- `lib/src/unpack15.dart` only after legacy compressed coverage exists

**C reference:** `unpackinline.cpp::Unpack::CopyString` and
`unpack15.cpp::CopyString15`.

Tasks:

1. Keep the existing byte loop as a selectable reference implementation during
   development and benchmarking.
2. Add fast paths away from the circular-window boundary:
   - `distance == 1`: fill with the preceding byte;
   - `distance >= length`: one non-overlapping `setRange`;
   - `distance < length`: copy the initial pattern, then double the produced
     range with non-overlapping `setRange` calls until complete.
3. Retain guarded byte-wise copying at window boundaries and for malformed
   distances.
4. Preserve zero-fill behavior for invalid distances and first-window access.
5. Benchmark the pattern-doubling implementation against both:
   - the existing byte loop;
   - fixed `min(distance, remaining)` chunking.
6. Keep the fastest implementation independently for VM/JIT and AOT if results
   differ materially and the distinction can be maintained cleanly.

Guardrails:

- Plain `memmove` semantics are incorrect when `distance < length`.
- Every `setRange` used by the doubling algorithm must be non-overlapping.
- Source bytes written earlier in the same match are intentionally reused.
- Circular-window wrap must leave `_unpPtr` normalized exactly as before.

Expected result: reduced time in the primary decompressor inner copy loop.

Exit gate: every direct match-copy test, archive golden, solid fixture, and
Vagabond cross-check passes. Keep only if a representative extraction workload
improves by at least 3% or profiling shows a clear CPU reduction without a
regression elsewhere.

### Phase 5 — Reduce listing and header-parsing overhead

**Files:**

- `lib/io.dart`
- `lib/src/byte_source.dart`
- `lib/src/raw_reader.dart`
- `lib/src/archive_reader.dart`

**C reference:** `arcread.cpp`, `rawread.cpp`, and optionally `qopen.cpp`.

Tasks, in increasing risk order:

1. Track position inside `FileByteSource` and return it without calling
   `RandomAccessFile.position()` for every header.
2. Cache file length after the first lookup.
3. Replace `RawReader`'s append-then-flatten representation with a contiguous
   typed buffer with explicit capacity and logical length.
4. Avoid rebuilding a seven-byte flat buffer before the remainder of the same
   header is read.
5. Add a header-oriented read-ahead cache that:
   - services small sequential header reads from memory;
   - invalidates or repositions correctly on seek;
   - does not force large payload reads during `list()`;
   - handles encrypted-header block alignment.
6. Where state already proves the next absolute position, avoid redundant
   asynchronous position queries. Keep source position and `_blockPos`
   assertions in debug builds.
7. Benchmark synchronous file primitives behind the existing asynchronous
   public API. Retain them only if they improve list latency without starving
   event-loop-sensitive callers.
8. Treat RAR Quick Open support as a separate optional experiment after the
   universal path reaches its target. It can greatly help compatible modern
   archives but cannot replace normal scanning for older archives.

Guardrails:

- Listing must not read complete stored payloads merely to maintain a rolling
  buffer.
- SFX scanning, encrypted headers, comments, service blocks, symlink targets,
  and multi-volume seeks must keep exact physical offsets.
- `ByteSource` remains implementable for web, memory, network, and custom
  sources.

Expected result: at least 2x faster listing on the Vagabond archive, with gains
scaling with entry count.

Exit gate: listing target met and all header/corpus tests pass.

### Phase 6 — Cache RAR5 KDF state and reduce AES allocation

**Files:**

- `lib/src/kdf5.dart`
- `lib/src/aes.dart`
- `lib/src/unpacker.dart`
- `lib/src/archive_reader.dart`

**C reference:** `crypt5.cpp::CryptData::SetKey50` and Rijndael CBC code.

Tasks:

1. Derive RAR5 KDF state once per `(password, salt, lg2Count)` and reuse its AES
   key, hash key, and password-check value for decryption and verification.
2. Use a small bounded per-reader cache or entry-owned derived context. Do not
   introduce process-global password state.
3. Clear or release password-derived state when the archive closes.
4. Change AES-CBC decryption to write directly into `Uint8List` output.
5. Reuse one 16-byte block scratch buffer instead of allocating `sublist` and
   `List.of` objects for every AES block.
6. Reuse the expanded AES key schedule for per-header IV changes.
7. Avoid wrapping an already typed decrypted result in `Uint8List.fromList`.

Guardrails:

- Cache keys include password, full salt, and iteration exponent.
- Derived material must not leak across unrelated archive readers.
- CBC IV state remains per stream or per encrypted header as required.
- Wrong-password checks occur before decompression where the format permits.

Expected result: large improvement for encrypted archives, especially high
iteration counts and entries carrying both CRC-MAC and BLAKE2-MAC.

Exit gate: all encrypted fixtures pass with correct and incorrect passwords;
record KDF invocation counts and encrypted benchmark deltas.

### Phase 7 — Optimize CRC only if it remains material

**Files:** `lib/src/crc.dart` and CRC tests.

**C reference:** `crc.cpp`.

Experiments:

1. Mask the incoming CRC once and remove redundant per-byte
   `& 0xFFFFFFFF` operations if tests prove identical public semantics.
2. Implement slicing-by-8 first, using typed tables initialized once per
   isolate.
3. Implement slicing-by-16 only if slicing-by-8 leaves measurable CRC time and
   the additional tables improve end-to-end throughput.
4. Keep the byte path for short headers and short payload fragments where table
   setup and wide-loop overhead do not pay back.
5. Benchmark warm and cold isolate behavior, JIT and AOT, small headers, and
   multi-megabyte payloads.

Guardrails:

- Preserve `crc32(startCrc, data, offset, length)` incremental semantics.
- Avoid unaligned reads that are slower in Dart than direct indexed loads.
- Keep tables behind one lazily initialized object if startup cost is material.
- Compare end-to-end extraction, not only a synthetic CRC loop.

Keep criterion: at least 3% representative extraction improvement or a clearly
documented improvement to test/store workloads without regressions.

### Phase 8 — Reprofile and consider a persistent bit reservoir

**Files:** `lib/src/bit_input.dart` plus decoders only if API changes require it.

**C reference:** `getbits.hpp` and `unpackinline.cpp::DecodeNumber`.

Proceed only if post-phase profiling still shows bit loading as a leading hot
spot.

Experiments:

1. Maintain a persistent 32- or 64-bit reservoir and valid-bit count.
2. Refill in batches instead of reconstructing a field from indexed byte loads
   on every `getbits()` call.
3. Preserve `getbits`, `getbits32`, `getbits64`, `addbits`, `getChar`, and
   external-buffer semantics.
4. Measure the interaction with PPMd, whose byte reader shares `BitInput`
   position state.
5. Retain the existing implementation as the reference until all malformed and
   end-of-buffer tests pass.

Do not substitute `rawGetBe4` mechanically for the current three-byte
`getbits()` implementation; that alone is not a batched decoder and can add a
fourth indexed load.

Keep criterion: at least 3% improvement on RAR 4 or RAR 5 compressed workloads
with no regression on PPMd or small archives.

## 6. Commit and rollback strategy

Keep each phase independently reviewable:

1. tests and baseline documentation;
2. packed-input allocation removal;
3. output sink and exact allocation;
4. incremental hashing and test mode;
5. match-copy experiment;
6. listing/header I/O;
7. encryption cache and AES allocation;
8. CRC experiment;
9. bit-reservoir experiment.

Inner-loop experiments must be removable without reverting correctness or
architecture work. Do not mix `_copyString`, CRC, and bit-input changes in one
benchmark or commit.

For every experimental commit, record:

- hypothesis;
- changed hot path;
- before/after benchmark table;
- correctness commands and results;
- peak memory or allocation observation where relevant;
- keep/revert decision.

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Match replication becomes memmove-like | Direct overlap tests, byte-loop reference, full cross-check |
| Unknown unpacked size causes huge allocation | Dedicated growable sink; never allocate `int64Ndf` |
| Solid file state is reset with output state | Keep window/decoder lifetime separate from per-file sink lifetime |
| Test mode skips post-filters | Feed only final emitted bytes into the hash sink |
| Incremental CRC changes chaining | Chunk-boundary vectors and non-default start-state tests |
| Read-ahead consumes payload unnecessarily | Header-oriented bounded cache with seek invalidation |
| Encrypted header offsets drift | Physical-position tests for IV and AES-aligned blocks |
| KDF cache crosses security boundary | Per-reader bounded cache and cleanup on close |
| Optimized code helps JIT but hurts AOT/web | Benchmark relevant target modes before accepting |
| Microbenchmark improves but extraction regresses | End-to-end keep thresholds and phase rollback |

## 8. Final deliverables

- Optimized pure-Dart implementation with no public API regression.
- New unit tests for short reads, output sinks, overlap copying, incremental
  hashing, and encrypted-context reuse.
- Before/after results appended to `BENCH-001-dart_unrar_vs_neoasis_unrar.md`.
- `HANDOFF-001-optimization-of-the-port.md` updated or marked superseded after
  the plan is completed.
- Changelog and milestone updates describing user-visible performance gains.
- A final summary listing accepted and rejected experiments, correctness gate
  results, benchmark deltas, and remaining native hardware advantage.
