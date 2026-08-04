# neoasis_unrar

A pure Dart implementation of the UnRAR library for reading and extracting
RAR archives, ported from the official RARLAB C source code (unrarsrc 7.2.3).

No native code, no FFI, no `dart:io` dependency in the core library - it works
in any Dart environment, including Flutter on all platforms and the web.

## Status

**All eight milestones complete.** The library is a full-featured pure Dart
RAR reader with no `dart:io` dependency in its core. See
[MILESTONES.md](MILESTONES.md) for the complete milestone log.

Implemented (ported and unit-tested):
- CRC32 and the legacy RAR 1.4 checksum (`crc.cpp`)
- Big/little-endian raw integer readers (`rawint.hpp`)
- Bit-level input reader used by the decompressor (`getbits.cpp`)
- Sequential byte reader with variable-length integer (vint) support (`rawread.cpp`)
  — `Uint8List`-backed chunk buffer for zero-boxing performance
- RAR 4.x unicode file name decoder (`encname.cpp`)
- Archive signature / format detection for RAR 1.4, RAR 4.x and RAR 5.0 (`archive.cpp`)
- Block iteration and main/file header parsing for RAR 1.4, RAR 4.x and RAR 5.0 (`arcread.cpp`)
  — entry name, sizes, CRC32, flags, timestamps, host OS
- Extraction of stored (method 0) files with CRC32 verification (`unpack.cpp`)
- RAR 5.0/7.0 decompression: LZ-based unpacker with Huffman decode tables,
  delta, LZ/DCX/ARM/SPARC/IA64/PPC/RISC-V filters, solid-stream window carry
  (`unpack5.cpp`, `unpackinline.cpp`) — `extractFile`, `extractAll`, `testArchive`
- RAR 4.x decompression (unpVer 20/26/29): LZSS window decoder and the PPMd
  range-coder + model variant, with solid-stream state reuse
  (`unpack20.cpp`, `unpack30.cpp`, `model.cpp`, `suballoc.cpp`)
- **Encryption (M6)**: AES-128/256, SHA-1, SHA-256, HMAC-SHA256, RAR 4.x KDF
  and RAR 5.0 PBKDF2 KDF; RAR 4.x + RAR 5.0 data decryption; RAR 3/4 and
  RAR 5.0 header decryption (`-hp`); password API
- **Multi-volume extraction (M7)**: `NextVolumeName` port; `VolumeResolver`
  callback; `openRarFile` auto-chains volumes from the file system; fragment
  assembly with last-part CRC
- **Extra field metadata (M8)**:
  - `FHEXTRA_REDIR`: symlinks, junctions, hard links → `redirectType`,
    `redirectTarget`, `isRedirect`
  - `FHEXTRA_UOWNER`: Unix owner/group (name + numeric IDs) → `unixOwner`
  - `FHEXTRA_HTIME`: high-precision timestamps (Unix + nanoseconds, Windows
    FILETIME) → `createdTime`, `accessedTime`, precision mtime
  - RAR 4.x Unix symlink auto-detection from `fileAttr & 0xF000`
  - RAR 1.4 archive format (`rarFmt14`) header reading
  - `Uint8List` performance pass throughout all hot paths

Not yet implemented:
- Recovery record reconstruction (`recvol5.cpp` Reed-Solomon over GF(2^16))
- Multi-volume splicing of encrypted split entries is supported but the
  volume-resolver callback must open encrypted volumes with the same password
- NTFS alternate data streams (`FHEXTRA_SUBDATA`)

See [MILESTONES.md](MILESTONES.md) for the full roadmap.

## Usage

```dart
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:neoasis_unrar/io.dart';

void main() async {
  // Open an archive. Multi-volume archives are chained automatically.
  // Supply password: for encrypted archives.
  final archive = await openRarFile('archive.rar');
  // final archive = await openRarFile('encrypted.rar', password: 'secret');

  print('Format: ${archive.format}');
  print('Solid:  ${archive.info.solid}');

  for (final entry in await archive.list()) {
    print('${entry.name}  ${entry.packSize} → ${entry.unpSize} bytes');
    if (entry.isRedirect) {
      print('  → symlink to ${entry.redirectTarget}');
    }
    if (entry.unixOwner != null) {
      print('  owner ${entry.unixOwner!.ownerName} (${entry.unixOwner!.ownerId})');
    }
  }

  // Stored, compressed, encrypted, and split-volume files all extract
  // with CRC/MAC verification.
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
