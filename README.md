# neoasis_unrar

A pure Dart implementation of the UnRAR library for reading and extracting
RAR archives, ported from the official RARLAB C source code (unrarsrc 7.2.3).

No native code, no FFI, no `dart:io` dependency in the core library - it works
in any Dart environment, including Flutter on all platforms and the web.

## Status

This is an early-stage port. Current milestone: **archive reading + listing**
(extraction, encryption, and recovery records are planned — see
[MILESTONES.md](MILESTONES.md)).

Implemented (ported and unit-tested):
- CRC32 and the legacy RAR 1.4 checksum (`crc.cpp`)
- Big/little-endian raw integer readers (`rawint.hpp`)
- Bit-level input reader used by the decompressor (`getbits.cpp`)
- Sequential byte reader with variable-length integer (vint) support (`rawread.cpp`)
- RAR 4.x unicode file name decoder (`encname.cpp`)
- Archive signature / format detection (`archive.cpp`)
- Block iteration and main/file header parsing for RAR 4.x and RAR 5.0 (`arcread.cpp`)
  - sufficient to list entries: name, sizes, CRC32, flags, times

Not yet implemented (future milestones):
- Data extraction (decompression), headers encryption, RAR 1.4 support,
  recovery records, extra fields (links, owners, streams), and more.

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

  await archive.close();
}
```

## License

Portions of this code are derived from the UnRAR utility by Alexander Roshal
(RARLAB). See [LICENSE](LICENSE) for the full license text and usage
restrictions. Note that the UnRAR license permits handling RAR archives but
prohibits re-creating the RAR compression algorithm.
