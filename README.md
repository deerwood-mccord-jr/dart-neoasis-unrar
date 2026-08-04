# neoasis_unrar

A pure Dart implementation of the UnRAR library for reading and extracting
RAR archives, ported from the official RARLAB C source code (unrarsrc 7.2.3).

No native code, no FFI, no `dart:io` dependency in the core library - it works
in any Dart environment, including Flutter on all platforms and the web.

## Status

This is an early-stage port. Current milestone: **Milestone 6 complete —
RAR 4.x and RAR 5.0/7.0 extraction including compressed and encrypted data,
header decryption (`-hp`), and a password API** (recovery records and volumes
are still planned — see [MILESTONES.md](MILESTONES.md)).

Implemented (ported and unit-tested):
- CRC32 and the legacy RAR 1.4 checksum (`crc.cpp`)
- Big/little-endian raw integer readers (`rawint.hpp`)
- Bit-level input reader used by the decompressor (`getbits.cpp`)
- Sequential byte reader with variable-length integer (vint) support (`rawread.cpp`)
- RAR 4.x unicode file name decoder (`encname.cpp`)
- Archive signature / format detection (`archive.cpp`)
- Block iteration and main/file header parsing for RAR 4.x and RAR 5.0 (`arcread.cpp`)
  - sufficient to list entries: name, sizes, CRC32, flags, times
- Extraction of stored (method 0) files with CRC32 verification (`unpack.cpp`)
- RAR 5.0/7.0 decompression: LZ-based unpacker with Huffman decode tables,
  delta, LZ/DCX/ARM/SPARC/IA64/PPC/RISC-V filters, solid-stream window carry,
  and external-buffer input mode (`unpack5.cpp`, `unpackinline.cpp`) —
  `extractFile`, `extractAll`, `testArchive`
- RAR 4.x decompression (unpVer 20/26/29): LZSS window decoder and the PPMd
  range-coder + model variant, with solid-stream state reuse
  (`unpack20.cpp`, `unpack30.cpp`, `model.cpp`, `suballoc.cpp`)
- **Encryption (Milestone 6)**:
  - Pure Dart AES-128/256, SHA-1, SHA-256, HMAC-SHA256 (`aes.dart`, `sha1.dart`,
    `sha256.dart`, `hmac.dart`)
  - RAR 4.x KDF (SHA-1/0x40000 rounds, `crypt3.cpp`) and RAR 5.0 KDF
    (PBKDF2-HMAC-SHA256, `crypt5.cpp`)
  - RAR 5.0 file-data decryption with HASHMAC MAC verification
  - RAR 4.x file-data decryption (AES-128-CBC, per-file salt)
  - RAR 5.0 header decryption (`-hp`): per-header IV, block-aligned CBC
  - RAR 4.x / RAR 3 header decryption (`-hp`): 8-byte archive salt
  - Password API: `RarArchive.open(source, {String? password})` and
    `openRarFile(path, {String? password})`

Not yet implemented (future milestones):
- Multi-volume splicing, recovery records, extra fields (links, owners,
  streams), RAR 2.x legacy encryption, and more. RAR 1.5 (unpVer 15) is
  out of scope: the format predates every tool that can still create RAR
  archives, so no real test fixtures exist.

See [MILESTONES.md](MILESTONES.md) for the full roadmap.

## Usage

```dart
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:neoasis_unrar/io.dart';

void main() async {
  // Open an archive (supply password: for encrypted archives).
  final archive = await openRarFile('archive.rar');
  // final archive = await openRarFile('encrypted.rar', password: 'secret');

  print('Format: ${archive.format}');
  print('Solid:  ${archive.info.solid}');
  print('Locked: ${archive.info.locked}');

  for (final entry in await archive.list()) {
    print('${entry.name}  ${entry.packSize} -> ${entry.unpSize} bytes');
  }

  // Stored, RAR 5.0/7.0 compressed, and encrypted files extract with
  // CRC/MAC verification.
  await archive.extractAll((entry, data) {
    print('extracted ${entry.name}: ${data.length} bytes');
  });

  await archive.close();
}
```

## License

Portions of this code are derived from the UnRAR utility by Alexander Roshal
(RARLAB). See [LICENSE](LICENSE) for the full license text and usage
restrictions. Note that the UnRAR license permits handling RAR archives but
prohibits re-creating the RAR compression algorithm.
