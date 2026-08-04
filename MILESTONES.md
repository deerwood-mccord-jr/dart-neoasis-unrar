# Milestones

Roadmap for the pure Dart port of the UnRAR library, ported from the official
RARLAB C source (`unrarsrc 7.2.3`, vendored under
`../dart_unrar/third_party/unrar/`). The reference file(s) in parentheses are
the C sources each milestone ports.

Legend: ✅ done · 🔵 in progress · ⬜ planned

---

## 1. Scaffold + core foundation — ✅ done (commit `5c0a555`)

Project setup and the byte-level primitives every later milestone builds on.

- Package scaffold, license, CI-ready analyzer config (`lints/recommended`,
  strict casts/inference)
- `CRC32` table + incremental checksum and the legacy RAR 1.4 checksum
  (`crc.cpp`, `crc.hpp`)
- Big/little-endian raw integer readers and power-of-two helpers
  (`rawint.hpp`)
- Growable sequential byte reader (`RawReader`) with variable-length integer
  (vint) support, block CRCs (`rawread.cpp`, `rawread.hpp`)
- Bit-level input reader used by the decompressors (`getbits.cpp`,
  `getbits.hpp`)
- RAR 4.x unicode file-name decoder (`encname.cpp`, `encname.hpp`)
- DOS/Unix time conversion (`timefn.cpp`)
- `ByteSource` abstraction + `dart:io`-free core; file access in `lib/io.dart`
- Error model (`UnrarException` family)

## 2. Archive reading + listing — ✅ done (commit `6e4f118`)

Recognize an archive, walk its block/header stream, and list entries with all
header-level metadata.

- RAR signature / format detection incl. RAR 1.4, RAR 4.x, RAR 5.0 and future
  markers (`archive.cpp`)
- SFX stub scanning (`MAXSFXSIZE` window, `IsSignature`)
- RAR 4.x block + header parsing: main, file, service, protect, end-of-archive
  (`arcread.cpp`, `headers.hpp`)
- RAR 5.0 block + header parsing: main, file, service, crypt, end-of-archive
  (`arcread.cpp`, `headers5.hpp`)
- RAR 5.0 extra-area records (`ProcessExtra50`) — encryption (`FHEXTRA_CRYPT`)
  detection so entries report `isEncrypted`
- Entry model: name, packed/unpacked size, CRC32, times, method, flags,
  solid/split/encrypted/directory markers (`headers.hpp` `FileHeader`)
- `RarArchive.open / list / close` public API + example CLI
- Integration tests against a corpus of real archives (names/order/sizes
  verified against `unrar` 7.x) and self-contained volume fixtures

## 3. Extraction: stored files + verification — ✅ done (commit `f75c133`)

Decompress nothing, but ship the extraction pipeline so the API shape and
CRC verification land first.

- Unpacking loop: iterate entries, locate file data (`GetBlockHeader`,
  `SeekToNextBlock`), handle solid-archive state (`Unpack`)
- `UnpackMethod::M_STORE` (method 0, no compression) copy-out path
  (`unpack.cpp`)
- Data CRC32 verification after extraction (`crc.cpp`)
- Stream out unpacked bytes via a sink/callback (pure Dart, no file I/O in core)
- `extractFile` / `extractAll` / `testArchive` API surface (`extract.cpp`
  behavior)
- Per-header `dataOffset` tracking (absolute) so `extractFile` can seek
  straight to a file's data — this also makes stored solid archives work;
  reader rewinds to just past the main header before extracting
- Byte-exact integration tests against stored corpus archives (RAR 4.x and
  5.0, solid and non-solid) plus `extract_archive.dart` example CLI

## 4. Extraction: RAR 5.0/7.0 decompression — ✅ done (commit `f75c133`)

The largest single milestone. RAR 5.0/7.0 uses a custom LZ77-family decoder
(distance caches, length tables, filters, decode tables).

- `Unpack50` main decode loop, window management, match/literal decoding,
  decode tables + quick tables (`unpack50.cpp`, `unpack50frag.cpp`,
  `make_decode_tables.cpp`)
- Distance caches (recent distances, dist cache) and length tables
- Standard filters: delta, LZ (incl. 80-code DCX variant), ARM, SPARC, IA64,
  PPC, RISC-V — replaces the RAR VM (only the VM-based RAR 4.x filters are
  deferred to the RAR 4.x milestone)
- RAR 7.0 specifics: `UnpVer 70` decode tables, DCX (`ExtraDist`), 64-bit
  dict size limit (`UNPACK_MAX_DICT`)
- Solid-stream window carry: one persistent decompressor per archive, prior
  entries unpack-and-discarded so later entries' matches resolve correctly
  (`archive_reader.dart` gated on the main-header solid flag)
- External-buffer input mode with safe zero padding (`BitInput.external`) and
  RAR 5.0 dict-size computation from raw `unpVerRaw`
- Byte-exact integration tests: `basic_rar5.rar`, `with_dirs.rar`, `solid.rar`
  (147/141/125-byte files verified byte-for-byte and by CRC against `unrar`
  7.x); `UnsupportedMethodException` dispatch covered synthetically for RAR 4.x
  (RAR 7.x cannot produce RAR 4 archives, see §5)

## 5. Extraction: RAR 4.x decompression — ✅ done (commit `ae25ce9`)

Two families, versioned by `UnpVer`.

- v20/v29 LZSS window decoder (`unpack20.cpp`, `unpackinline.cpp`)
- v29 PPMd variant via the range coder + model (`unpack30.cpp`, `model.cpp`,
  `model.hpp`, `suballoc.cpp`)
- Old-version decoders gated by header `UnpVer` like the C code; dispatch wired
  in `Unpacker` for unpVer 20/26/29, including solid-stream state reuse
  (`Rar4Unpacker`)
- Shared `DecodeNumber`/`MakeDecodeTables` factored out of `unpack5.dart` for
  both RAR 4.x and RAR 5.0; `Unpack::GetChar` byte-wise reader added to
  `BitInput` for the PPMd range coder
- Note: RAR 7.x can no longer create RAR 4 archives, so the corpus cannot
  provide real RAR 4 compressed files; instead we rely on the libarchive RAR 4
  corpus (`test/fixtures/libarchive/rar4_*.rar`) verified byte-exact (size +
  CRC32) against `unrar` 7.x — including `rar4_ppmd_lzss.rar`, whose PPMd
  stream was additionally traced against the C reference model (`model.cpp`)
  char-by-char
- v15 (RAR 1.5) legacy decoder (`unpack15.cpp`) — small but optional, still
  ⬜ planned

## 6. Encryption — ⬜ planned

- AES-128 (RAR 4.x, `crypt2.cpp`, `crypt3.cpp`) and AES-256 + PBKDF2 (RAR 5.0,
  `crypt5.cpp`) — pure Dart crypto, no external dependency
- Header decryption (`-hp`): decrypt the crypt header, then header stream
  (`crypt.cpp`, `crypt.hpp`, `arcread.cpp` header decrypt path) — this is why
  `encrypted_headers.rar` currently throws
- Password API (`RarArchive.open(..., password: ...)`), password-check
  validation, wrong-password errors
- `crypt1.cpp` (RAR 2.x legacy) — optional

## 7. Volumes + recovery + integrity — ⬜ planned

- Multi-volume continuation during extraction: detect next volume name,
  open part N+1, splice file data across parts (`volume.cpp`, `volume.hpp`)
- Recovery records (`.rev` / RR blocks): `recvol3.cpp`, `recvol5.cpp` — parity
  reconstruction, large; defer unless needed
- End-of-archive flags (`EHFL_NEXTVOLUME`), split-entry handling, better
  error classification

## 8. Completeness + polish — ⬜ planned

- RAR 1.4 (`rarFmt14`) full header support (`headers.hpp` legacy fields)
- Extra fields: file redirection (links, symlinks, hard links) via
  `FHEXTRA_REDIR`, owners/streams (`FHEXTRA_UOWNER`, NTFS streams)
- File version info, high-precision times, comments/quick-open blocks
- Full `testArchive` parity, per-entry `isSolid` sequencing for solid archives
- Performance pass (avoid list-based buffers, `Uint8List` everywhere),
  web/compiler compatibility verification

---

## Cross-cutting notes

- **API stability:** the core library stays `dart:io`-free; file IO lives in
  `lib/io.dart`. Decompression output goes through a sink/callback so callers
  (and `lib/io.dart`) decide the destination.
- **Testing:** every ported primitive gets a unit test against a hand-built
  byte stream; real-archive behavior is locked down by the `dart_unrar` corpus
  integration suite and the committed `test/fixtures/vol.part*.rar`.
- **Extraction validity:** the C unpack code is heavily optimized with inline
  tables and 32/64-bit packed reads; the port favors readability first, then a
  dedicated performance pass (milestone 8).
- **RAR compression is proprietary:** the UnRAR license permits *reading* RAR
  archives; we must not re-implement the *writer*. See `LICENSE`.
