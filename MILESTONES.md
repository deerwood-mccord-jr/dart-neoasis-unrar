# Milestones

Roadmap for the pure Dart port of the UnRAR library, ported from the official
RARLAB C source (`unrarsrc 7.2.3`, vendored under
`../dart_unrar/third_party/unrar/`). The reference file(s) in parentheses are
the C sources each milestone ports.

Legend: ✅ done · 🔵 in progress · ⬜ planned · ❌ out of scope

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
- v15 (RAR 1.5) legacy decoder (`unpack15.cpp`) — ❌ out of scope: RAR 1.5
  archives exist only from the 1996-era RAR 1.5x tools and cannot be produced
  by the licensed `rar` CLI (7.x has no legacy-format switch) or any other
  modern tool, so no test fixture is obtainable. An unverifiable port would be
  worse than an explicit error; `Unpacker.unpack` keeps throwing
  `UnsupportedMethodException` for unpVer 15

## 6. Encryption — ✅ done (commit `48eccae`)

Pure Dart AES + PBKDF2 crypto, data decryption for both archive formats, and
header decryption (`-hp`), with a password API threaded through the public
surface.

- **Crypto foundation** — pure Dart, no external dependency:
  - SHA-1 (`sha1.dart`) including the `sha1_process_rar29` write-back variant
    used by the RAR 3.x/4.x KDF (`crypt3.cpp`)
  - SHA-256 + HMAC-SHA256 (`sha256.dart`, `hmac.dart`)
  - AES-128/192/256 block cipher with stateful AES-CBC decryptor
    (`aes.dart`, `rijndael.cpp`)
  - RAR 3.x/4.x KDF (`kdf3.dart`): SHA-1 / 0x40000 rounds, AES-128 key +
    CBC IV (`crypt3.cpp`, `SetKey30`)
  - RAR 5.0 KDF (`kdf5.dart`): PBKDF2-HMAC-SHA256, AES-256 key + hash key
    + password check value (`crypt5.cpp`, `SetKey50`/`pbkdf2`)
  - NIST AES vectors, PBKDF2 vectors, and RAR-specific KDF fixtures all
    covered by `test/crypto_test.dart` (90 crypto vector tests alone)

- **RAR 5.0 file-data decryption** — `Unpacker._decryptRar5`:
  - PBKDF2 key derived from the per-file `FHEXTRA_CRYPT` salt (16 bytes) and
    lg2Count
  - Optional password-check (`FHEXTRA_CRYPT_PSWCHECK`) verified before
    decryption to give early wrong-password errors
  - AES-256-CBC with the per-file IV; zero-padded packed stream (no separate
    check block — empirically confirmed against real fixtures)
  - When `FHEXTRA_CRYPT_HASHMAC` flag is set, the header's CRC32 field is a
    HMAC-SHA256 MAC; post-decrypt MAC verification via `crc32Mac` /
    `ConvertHashToMAC` from `crypt5.cpp`

- **RAR 4.x file-data decryption** — `Unpacker._decryptRar4`:
  - AES-128-CBC with SHA-1 KDF (`kdf3`) over per-file 8-byte salt
    (stored after the filename in the file header when `LHD_SALT` is set)
  - Zero-padded packed stream; CRC32 verification post-decrypt

- **RAR 5.0 header decryption (`-hp`)** — `ArchiveReader._parseCryptHead50` +
  `_readHeader50` decrypt path:
  - `HEAD_CRYPT` block (plaintext) carries archive-level salt and pswCheck;
    PBKDF2-derived key cached in `_rar5HeaderDecryptor`
  - Each subsequent header is prefixed with a 16-byte IV in the stream;
    `AesCbcDecryptor` re-initialised per header with the correct IV
  - AES-CBC block-alignment handled in `RawReader` (reads rounded up to
    16 bytes from source; logical header CRC is checked against the decrypted
    bytes up to `headerSize` to avoid zero-padding contamination)
  - `_nextBlockPos` accounts for `sizeInitV` + `alignedUp(headerSize)` so
    block iteration stays consistent after encryption

- **RAR 3/4 header decryption (`-hp`)** — `ArchiveReader._readHeader15`
  decrypt path:
  - 8-byte salt preamble read once, AES-128 key + IV derived via `kdf3`
  - `AesCbcDecryptor` stored as `_rar3HeaderDecryptor`; injected into
    `RawReader` for all subsequent header reads in the stream

- **`FHEXTRA_CRYPT` full parsing** — `_parseFhExtraCrypt` in
  `archive_reader.dart`: reads version, flags, lg2Count, salt, IV, pswCheck
  (8 bytes) + csum (4 bytes); SHA-256 integrity check on pswCheck matches
  `arcread.cpp ProcessExtra50`

- **Password API**: `RarArchive.open(source, {String? password})` and
  `openRarFile(path, {String? password})`; password is threaded through
  `ArchiveReader` → `Unpacker`; missing password throws `UnrarException`
  with a clear message

- **Integration tests** (102 tests total, all green):
  - `encrypted_data.rar` (RAR 5.0 HASHMAC): wrong-password rejection, byte-
    exact extraction of both files and `testArchive` pass
  - `encrypted_headers.rar` (RAR 5.0 `-hp`): list / extractAll / testArchive
    all pass with correct password; wrong password throws
  - `enc_store.rar` (method-0 + RAR 5.0 encryption): stored-file decrypt
    path exercised independently of the decompressor
  - `rar4_encrypted.rar`, `rar4_longpwd.rar` (crafted RAR 4.x + AES-128):
    plaintext verified byte-exact; wrong-password rejection tested
  - All 90 previous tests still pass (crypto vectors, format reading, RAR
    4.x / RAR 5.0 / RAR 7.0 compressed extraction, volumes)

## 7. Volumes + recovery + integrity — ✅ done (commit `815581c`)

- **`NextVolumeName` algorithm** (`pathfn.cpp`): pure string port; handles
  new-style (`part1→part2`, digit-carry with insert) and old-style
  (`.rar→.r00→.r01→…→.s00`) numbering conventions
- **`VolumeResolver` callback**: IO-free callback type threaded through
  `ArchiveReader` and `RarArchive.open`; `lib/io.dart` supplies a
  `fileVolumeResolver()` backed by `dart:io` that automatically locates
  next-volume files alongside the first part
- **`openRarFile`** wires the file-system resolver by default
  (`autoVolume: true`); pass `autoVolume: false` to disable
- **Multi-volume extraction** (`_unpackSplit`): assembles packed fragments
  from successive volumes into one buffer, uses the **last** part's CRC
  (the whole-file CRC) for verification rather than the per-part packed-
  data CRCs stored in earlier parts
- **Integration tests** against `test/fixtures/vol.part{1-4}.rar` (a real
  4-part RAR 5.0 volume set, 5000-byte binary file): byte-exact extraction
  via `extractFile` and `extractAll`, and explicit rejection without a
  resolver
- **Recovery records** (`recvol5.cpp`) deferred: relies on Reed-Solomon
  over GF(2^16) — no test fixtures exist and implementation scope is large
  relative to practical need

### 7b. REV recovery-volume reconstruction — ✅ done

Ported `RecVolumes5` (`recvol5.cpp`) + `RSCoder16` (`rs16.cpp`) so missing or
corrupt RAR 5.0 volumes can be rebuilt from `*.rev` files:

- **`Rs16`** (`lib/src/rs16.dart`): GF(2^16) tables (poly `0x1100B`),
  Cauchy encoder matrix (`C(R,j) = inv(R ^ j)`, `^` = XOR), Gauss-Jordan
  decoder-matrix inversion with the C's copy-back step. One caveat: the log
  table must be 32-bit wide — `gfLog[0] = 2*gfSize` (131070) overflows a
  `Uint16List` (truncates to 65534) and silently corrupts products with zero,
  which Python's big ints masked during validation
- **REV5 header parsing** (`lib/src/recvol.dart`): `readRevHeader`
  validates signature/`BlockCRC`, exposes `dataCount`, `recCount`, the
  absolute `recNum`, per-volume `RevVolumeInfo` (size + CRC32) and the ECC
  data offset
- **`restoreVolumes`**: byte-source-based core that CRC-validates every
  surviving volume, treats corrupt ones as missing, streams recovered chunks
  through a `RecoveredVolumeWriter` callback, and reports which indices were
  rebuilt. Round-verified against real RAR 7.23 fixtures (`rar a -v100k
  -rv5`): one-erasure, two-erasure, odd-size-last-volume, and corrupt-in-
  place repairs all byte-exact
- **`restoreRevArchive`** (`lib/io.dart`): enumerates sibling volumes on
  disk, generates canonical `partN` names, and writes rebuilt volumes
  (optionally to a separate `outputDir`)
- **Tests** (`test/rev_restore_test.dart`): fixture set checked into
  `test/fixtures/rev/` (3 data + 5 recovery volumes). Header parsing,
  byte-for-byte ECC re-encode, restore of 1/2 missing, odd-size, corrupt-
  treated-as-missing, too-many-missing, mismatched-set, and end-to-end disk
  restore incl. `outputDir`
- **Scope**: standalone `.rev` files only (as UnRAR). RAR 4.x `recvol3.cpp`
  not ported (RAR 7 can't create those).

## 8. Completeness + polish — ✅ done (commit `815581c`)

- **Extra area records** — all three remaining types ported from
  `ProcessExtra50` in `arcread.cpp`:
  - `FHEXTRA_REDIR` (0x05): file system redirection (Unix symlink, Windows
    symlink, junction, hard link, file copy); exposed as
    `ArchiveEntry.redirectType` ([FileSystemRedirect]) and
    `.redirectTarget`; `.isRedirect` convenience getter
  - `FHEXTRA_UOWNER` (0x06): Unix owner/group; string name and/or numeric
    UID/GID; exposed as `ArchiveEntry.unixOwner` ([UnixOwnerInfo])
  - `FHEXTRA_HTIME` (0x03): high-precision timestamps; Unix 32-bit ±
    nanoseconds or Windows FILETIME (100-ns); exposed as
    `ArchiveEntry.createdTime` and `.accessedTime`; `modifiedTime` is
    superseded when the record carries a higher-precision mtime;
    `winFileTimeToDateTime` ported from `RarTime::SetWin` in `timefn.cpp`

- **RAR 4.x Unix symlink detection**: `_parseFileHeader15` now checks
  `hostOs==HOST_UNIX && (fileAttr & 0xF000)==0xA000` and sets
  `redirectType = FileSystemRedirect.fsRedirUnixSymlink`, matching
  `ConvertFileHeader` in the C code

- **`ArchiveEntry` model expansion**: added `createdTime`, `accessedTime`,
  `redirectType`, `redirectTarget`, `redirectTargetIsDir`, `isRedirect`,
  `unixOwner` fields; `UnixOwnerInfo` class; all backward-compatible (new
  fields are optional / have defaults)

- **RAR 1.4 format** (`rarFmt14`) support: `_readHeader14Main` /
  `_readHeader14` ported from `Archive::ReadHeader14` in `arcread.cpp`;
  reads the 4-byte mark, main header flags, and file headers; CRC
  verification skipped (RAR 1.4 uses a 16-bit hash distinct from CRC32)

- **`Uint8List` performance pass**: `RawReader._data` replaced with a
  chunk-list backed by `Uint8List` chunks; `getB` returns `Uint8List`;
  `_readExact` and `_readUpTo` in `ArchiveReader` use `Uint8List` buffers;
  eliminates per-byte boxing in all header and block reads

- **Integration tests** (113 total, all green):
  - `symlinks.rar`: `FHEXTRA_REDIR` detected, `redirectType` and
    `redirectTarget` correct
  - `with_owner.rar`: `FHEXTRA_UOWNER` UID and GID fields populated
  - `with_htime.rar`: `FHEXTRA_HTIME` mtime field populated
  - `rar4_lz_normal.rar` (libarchive corpus): directories, files, and
    Unix symlink all listed correctly; `redirectType` set for the symlink

## 9. BLAKE2sp file hashes — ✅ done (commit `cea4cbd`)

Port the BLAKE2s/2sp tree hash used by RAR 5.0 `-htb` archives and verify
stored digests after extraction.

- **`blake2s.dart`** (`blake2s.cpp`, `blake2sp.cpp`): BLAKE2s core (`_g`,
  `_compress`, `_incrementCounter`, `_finalize` with last-block flagging) and
  the BLAKE2sp parallel-tree wrapper with fanout 8 / depth 2, node-depth and
  node-offset parameterisation, 512-byte round feeding, tail distribution to
  leaves, and root mixing (`InitHashState`-style parameter blocks from
  `hash.cpp`)
- **`FHEXTRA_HASH` parsing**: `_processExtra50` now reads the hash record
  (type vint + digest) for `FHEXTRA_HASH_BLAKE2` (0x00), mirroring
  `arcread.cpp ProcessExtra50`
- **`ArchiveEntry` model expansion**: `FileHashType` enum (`none`/`blake2`)
  exposed as `hashType`, plus `blake2Digest` (32 bytes)
- **Verification wiring** in `Unpacker`: after extraction, the plaintext is
  hashed with `Blake2Sp` and compared to the stored digest. For encrypted
  RAR 5.0 entries (`FHEXTRA_CRYPT_HASHMAC`) the stored 32 bytes are
  `hmacSha256(hashKey, digest)` per `ConvertHashToMAC` (`crypt5.cpp`); the
  HMAC is recomputed with the KDF-derived hash key. CRC MAC verification
  now skips entries whose `FHFL_CRC32` flag is absent (CRC 0). Wired through
  `unpack`, `unpackFromBuffer`, `_store`, `_unpack5`, `_unpack4`, and the
  multi-volume split path
- **Unit tests** (`test/blake2s_test.dart`): empty-hash vector from
  `HashValue::Init`, single-block and multi-block digests matching `rar -htb`
  output (`fox.txt`, `blob.bin`), and incremental chunking equivalence
  (1/2/63/64/65/127/128/512/1000) — the last caught and fixed a missing
  zero-pad in `_finalize`'s partial-block path
- **Integration tests** (123 total, all green):
  - `blake2.rar` (created with `rar a -htb`): entries report
    `hashType=blake2` + 32-byte digests; `extractAll` is byte-exact against
    `test/fixtures/blake2_ref/{fox.txt,blob.bin}`; stored digest equals
    `Blake2Sp(reference)`
  - `blake2_enc.rar` (`-htb -ptestpass`): encrypted entries verify via the
    BLAKE2 MAC; byte-exact with the correct password, `UnrarException` with a
    wrong one
  - archives created without `-htb` expose `hashType=none` / `null` digest

## 10. Pure-Dart optimization pass — ✅ done (IMPL-0001)

- Padded typed packed input removes decoder setup copies while preserving safe
  lookahead at the logical end of compressed data.
- Exact-size and discard output sinks perform CRC32, Checksum14, and BLAKE2sp
  incrementally; archive test mode no longer retains extracted payloads.
- RAR 3/4 and RAR 5 decoders share optimized overlap-safe LZ match copying.
- Header parsing uses one contiguous typed buffer; file sources cache physical
  position and length rather than querying the OS for every header.
- RAR5 KDF results are reused for decrypt/check/MAC operations within the
  reader and cleared on close; AES-CBC reuses a block scratch buffer.
- CRC32 uses a tested slicing-by-8 path for payloads and the short byte path
  for tails. The higher-risk bit-reservoir experiment was not warranted by the
  available post-change measurements.
- Full analyzer and 171-test gates pass. See
  `devdocs/BENCH-001-dart_unrar_vs_neoasis_unrar.md` §9 for measurements.

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
