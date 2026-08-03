# neoasis_unrar

A pure Dart implementation of the UnRAR library for reading and extracting
RAR archives, ported from the official RARLAB C source code (unrarsrc 7.2.3).

No native code, no FFI, no `dart:io` dependency in the core library - it works
in any Dart environment, including Flutter on all platforms and the web.

## Status

This is an early-stage port. Current milestone: **RAR 5.0/7.0 extraction
including compressed data** (RAR 4.x decompression, encryption, and recovery
records are still planned — see [MILESTONES.md](MILESTONES.md)).

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

Not yet implemented (future milestones):
- RAR 4.x compressed-data decompression (LZSS/PPMd), header/data encryption,
  RAR 1.4 support, multi-volume splicing, recovery records, extra fields
  (links, owners, streams), and more.

See [MILESTONES.md](MILESTONES.md) for the full roadmap.

## Usage

```dart
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:neoasis_unrar/io.dart';

void main() async {
  final archive = await RarArchive.open(FileByteSource(File('archive.rar')));

  print('Format: ${archive.format}');
  print('Solid:  ${archive.info.solid}');
  print('Locked: ${archive.info.locked}');

  for (final entry in await archive.list()) {
    print('${entry.name}  ${entry.packSize} -> ${entry.unpSize} bytes');
  }

  // Stored and RAR 5.0/7.0 compressed files extract with CRC verification.
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
