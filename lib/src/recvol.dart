/// RAR 5.0 recovery volume (`*.rev`) parsing and reconstruction, ported from
/// the RARLAB UnRAR `RecVolumes5` class (`recvol5.cpp`).
///
/// A `*.rev` file starts with the `Rar!\x1aRev` signature and a REV5 header
/// describing the data volumes it protects. The remaining bytes are the
/// Reed-Solomon error-correction stream for that recovery level. Missing or
/// corrupt RAR volumes are rebuilt by combining the surviving volumes and
/// the recovery streams with an [Rs16] decoder.
///
/// The core stays `dart:io`-free: volumes are passed in as [ByteSource]s and
/// recovered data is streamed out through a [RecoveredVolumeWriter] callback.
/// `lib/io.dart` provides a file-system based wrapper that enumerates
/// volumes on disk.
library;

import 'dart:typed_data';

import 'byte_source.dart';
import 'crc.dart';
import 'raw_int.dart';
import 'rs16.dart';
import 'unrar_error.dart';

/// REV5 signature: `Rar!\x1aRev`.
const List<int> rev5Sign = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x52, 0x65, 0x76];

/// Maximum header size accepted for a REV5 header, matching `ReadHeader`.
const int _maxRevHeaderSize = 0x100000;

/// Maximum number of volumes, matching `MaxVolumes` in `recvol5.cpp`.
const int maxRevVolumes = 65535;

/// Size of the signature plus the two 32-bit fields that precede the header
/// body (signature 8 bytes + block CRC + header size).
const int _revPrefixSize = 16;

/// Size/length info for one data volume, read from a REV5 header.
class RevVolumeInfo {
  const RevVolumeInfo({required this.fileSize, required this.crc32});

  /// Size of the volume file in bytes.
  final int fileSize;

  /// CRC32 of the entire volume file.
  final int crc32;
}

/// A parsed REV5 header (mirrors the fields read by `RecVolumes5::ReadHeader`).
class RevHeader {
  RevHeader({
    required this.dataCount,
    required this.recCount,
    required this.recNum,
    required this.revCrc,
    required this.volumes,
    required this.eccOffset,
  });

  /// Number of data (RAR) volumes.
  final int dataCount;

  /// Number of recovery (REV) volumes.
  final int recCount;

  /// Absolute index of this recovery volume within all
  /// `dataCount + recCount` volumes.
  final int recNum;

  /// CRC32 of this recovery volume's error-correction data.
  final int revCrc;

  /// Size and CRC of every data volume, in order.
  final List<RevVolumeInfo> volumes;

  /// Offset in the file where the error-correction data begins.
  final int eccOffset;

  /// `dataCount + recCount`.
  int get totalCount => dataCount + recCount;
}

/// A recovery volume (`*.rev` file) with its parsed header.
class RevVolume {
  const RevVolume({required this.header, required this.source});

  final RevHeader header;
  final ByteSource source;
}

/// Writes one chunk of recovered volume data.
///
/// [dataVolumeIndex] is the index of the data volume being rebuilt. [data]
/// is a temporary buffer valid only for the duration of the call and [length]
/// is the number of valid bytes at its start; the implementation must copy
/// any bytes it wants to keep.
typedef RecoveredVolumeWriter = Future<void> Function(
    int dataVolumeIndex, Uint8List data, int length);

/// Reads and validates a REV5 header from [source]'s current position,
/// mirroring `RecVolumes5::ReadHeader`.
///
/// Returns `null` when the source does not contain a valid REV5 header
/// (wrong signature, bad block CRC, unsupported version, or truncated data).
/// On success the source is positioned right after the header body, i.e. at
/// the start of the error-correction data.
Future<RevHeader?> readRevHeader(ByteSource source) async {
  final short = await source.read(_revPrefixSize);
  if (short.length < _revPrefixSize) return null;

  for (var i = 0; i < rev5Sign.length; i++) {
    if (short[i] != rev5Sign[i]) return null;
  }

  final headerSize = rawGet4(short, 12);
  final blockCrc = rawGet4(short, 8);
  if (headerSize > _maxRevHeaderSize || headerSize <= 5) return null;

  final body = await source.read(headerSize);
  if (body.length < headerSize) return null;

  // CRC32 of the 4-byte size field followed by the header body.
  var crc = crc32(0xffffffff, short, 12, 4);
  crc = crc32(crc, body) ^ 0xffffffff;
  if (crc != blockCrc) return null;

  if (body[0] != 1) return null; // Version check.

  final dataCount = rawGet2(body, 1);
  final recCount = rawGet2(body, 3);
  final recNum = rawGet2(body, 5);
  final totalCount = dataCount + recCount;
  if (recNum >= totalCount || totalCount > maxRevVolumes) return null;

  final revCrc = rawGet4(body, 7);
  final volumes = <RevVolumeInfo>[];
  var offset = 11;
  for (var i = 0; i < dataCount; i++) {
    volumes.add(RevVolumeInfo(
      fileSize: rawGet8(body, offset),
      crc32: rawGet4(body, offset + 8),
    ));
    offset += 12;
  }

  return RevHeader(
    dataCount: dataCount,
    recCount: recCount,
    recNum: recNum,
    revCrc: revCrc,
    volumes: volumes,
    eccOffset: _revPrefixSize + headerSize,
  );
}

/// Rebuilds missing or corrupt RAR 5.0 volumes from recovery volumes,
/// mirroring `RecVolumes5::Restore`.
///
/// [dataVolumes] has one entry per data volume (`reference.dataCount` entries
/// total); `null` means the volume is missing and will be reconstructed.
/// [revVolumes] lists the available recovery volumes in any order; each one's
/// header assigns it an absolute index via [RevHeader.recNum].
///
/// Every present volume is validated against its stored CRC32 before use:
/// volumes whose CRC does not match are treated as missing, and corrupt
/// recovery volumes are ignored. [writeChunk] is invoked for each recovered
/// chunk of every rebuilt volume, in increasing index order.
///
/// Throws [UnrarException] when reconstruction is impossible (no volumes
/// missing, too many missing, or an inconsistent volume set). Returns the
/// list of data-volume indices that were rebuilt.
Future<List<int>> restoreVolumes({
  required List<ByteSource?> dataVolumes,
  required List<RevVolume> revVolumes,
  required RecoveredVolumeWriter writeChunk,
  int chunkSize = 1 << 20,
}) async {
  if (revVolumes.isEmpty) {
    throw const UnrarException('No recovery volumes found');
  }
  if (chunkSize <= 0 || chunkSize.isOdd) {
    throw ArgumentError.value(
        chunkSize, 'chunkSize', 'must be a positive even number');
  }

  final reference = revVolumes[0].header;
  final nd = reference.dataCount;
  final nr = reference.recCount;
  if (nd == 0 || nr == 0 || nd + nr > maxRevVolumes) {
    throw const UnrarException('Invalid recovery volume header');
  }
  if (dataVolumes.length != nd) {
    throw ArgumentError.value(
        dataVolumes.length, 'dataVolumes', 'expected $nd entries');
  }

  final validFlags = List<bool>.filled(nd + nr, false);
  final revByIndex = <int, RevVolume>{};

  for (final rev in revVolumes) {
    final header = rev.header;
    if (header.dataCount != nd ||
        header.recCount != nr ||
        !_sameVolumes(header.volumes, reference.volumes)) {
      throw const UnrarException(
          'Recovery volumes belong to different archives');
    }
    final recNum = header.recNum;
    if (recNum < nd || recNum >= nd + nr) {
      continue;
    }
    if (revByIndex.containsKey(recNum)) {
      throw UnrarException('Duplicate recovery volume index: $recNum');
    }
    revByIndex[recNum] = rev;
  }

  // Validate every present data volume against its stored CRC32. Volumes
  // that fail the check are treated as missing.
  var missing = 0;
  for (var i = 0; i < nd; i++) {
    final source = dataVolumes[i];
    if (source == null) {
      missing++;
      continue;
    }
    await source.seek(0);
    final crc = await _crcFromSource(source);
    if (crc == reference.volumes[i].crc32) {
      validFlags[i] = true;
    } else {
      missing++;
    }
  }

  // Validate every recovery volume against its own stored RevCRC.
  var validRev = 0;
  for (final entry in revByIndex.entries) {
    final rev = entry.value;
    await rev.source.seek(rev.header.eccOffset);
    final crc = await _crcFromSource(rev.source);
    if (crc == rev.header.revCrc) {
      validFlags[entry.key] = true;
      validRev++;
    }
  }

  if (missing == 0) {
    throw const UnrarException('All volumes are present');
  }
  if (missing > validRev) {
    throw UnrarException(
        'Cannot fix archive: $missing volume(s) missing, '
        'but only $validRev valid recovery volume(s)');
  }

  final rs = Rs16();
  if (!rs.init(nd, nr, validityFlags: validFlags)) {
    throw const UnrarException('Failed to initialize recovery decoder');
  }

  // Reset all used sources to their stream start. Data volumes are read from
  // byte 0; recovery volumes from the start of their ECC data.
  final dataSource = <int, ByteSource>{};
  for (var i = 0; i < nd; i++) {
    if (validFlags[i]) {
      await dataVolumes[i]!.seek(0);
      dataSource[i] = dataVolumes[i]!;
    }
  }
  final revSource = <int, ByteSource>{};
  for (final entry in revByIndex.entries) {
    if (validFlags[entry.key]) {
      await entry.value.source.seek(entry.value.header.eccOffset);
      revSource[entry.key] = entry.value.source;
    }
  }

  // Stream reconstruction, chunk by chunk.
  final slots = List.generate(nd, (_) => Uint8List(chunkSize));
  final outputs = List.generate(missing, (_) => Uint8List(chunkSize));
  final remaining = List<int>.of(reference.volumes.map((v) => v.fileSize));
  final recovered = <int>[
    for (var i = 0; i < nd; i++)
      if (!validFlags[i]) i
  ];

  while (true) {
    var maxRead = 0;

    // For each data slot, read its next chunk either from the volume itself
    // or, when it is missing, from the next valid recovery volume.
    var j = nd;
    for (var i = 0; i < nd; i++) {
      final ByteSource source;
      if (validFlags[i]) {
        source = dataSource[i]!;
      } else {
        while (!validFlags[j]) {
          j++;
        }
        source = revSource[j]!;
        j++;
      }
      final got = await source.read(chunkSize);
      final n = got.length;
      slots[i].fillRange(0, chunkSize, 0);
      if (n > 0) slots[i].setRange(0, n, got);
      if (n > maxRead) maxRead = n;
    }

    if (maxRead == 0) break;

    // Round the processing region up to whole 16-bit words: the final byte of
    // an odd-sized volume is handled as part of a zero-padded word.
    final procLen = maxRead + (maxRead & 1);

    for (var o = 0; o < missing; o++) {
      outputs[o].fillRange(0, procLen, 0);
    }
    for (var i = 0; i < nd; i++) {
      rs.updateEccAll(i, slots[i], 0, procLen, outputs, 0);
    }

    // Persist the recovered chunks.
    var outputIdx = 0;
    for (var i = 0; i < nd; i++) {
      if (validFlags[i]) continue;
      final size = procLen < remaining[i] ? procLen : remaining[i];
      if (size > 0) {
        await writeChunk(i, outputs[outputIdx], size);
        remaining[i] -= size;
      }
      outputIdx++;
    }
  }

  // Validate that every rebuilt volume received its full expected size.
  for (var i = 0; i < nd; i++) {
    if (!validFlags[i] && remaining[i] != 0) {
      throw UnrarException(
          'Recovery produced ${reference.volumes[i].fileSize - remaining[i]} '
          'of ${reference.volumes[i].fileSize} bytes for volume $i');
    }
  }

  return recovered;
}

bool _sameVolumes(List<RevVolumeInfo> a, List<RevVolumeInfo> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i].fileSize != b[i].fileSize || a[i].crc32 != b[i].crc32) {
      return false;
    }
  }
  return true;
}

/// Streams the entire [source] from its current position, returning the
/// standard CRC32 (`crc32(0xffffffff, ...) ^ 0xffffffff`) of its contents.
Future<int> _crcFromSource(ByteSource source) async {
  var crc = 0xffffffff;
  final buffer = Uint8List(1 << 16);
  while (true) {
    final chunk = await source.read(buffer.length);
    if (chunk.isEmpty) break;
    crc = crc32(crc, chunk);
  }
  return crc ^ 0xffffffff;
}
