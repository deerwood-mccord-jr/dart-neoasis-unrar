import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/io.dart';
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:neoasis_unrar/src/rs16.dart';
import 'package:test/test.dart';

/// Tests for RAR 5.0 `*.rev` recovery-volume reconstruction, using a real
/// RAR 7.23 fixture set created with `rar a -v100k -rv5` (3 data volumes,
/// 5 recovery volumes; data files `data1.bin` 100000 bytes, `data2.bin`
/// 200000 bytes). The last data volume is deliberately smaller (96197 bytes)
/// to exercise odd-size reconstruction.
const _dir = 'test/fixtures/rev';

void main() {
  final fixture = Directory(_dir);
  if (!fixture.existsSync()) {
    test('rev fixtures not found', () {},
        skip: 'run from the repository root with fixtures present');
    return;
  }

  Future<Uint8List> readFile(String name) async =>
      await File('$_dir/$name').readAsBytes();

  Uint8List slice(Uint8List bytes, int offset, int length) =>
      Uint8List.fromList(bytes.sublist(offset, offset + length));

  group('REV5 header', () {
    test('parses the reference rev header', () async {
      final source = FileByteSource(File('$_dir/arc.part1.rev'));
      addTearDown(source.close);
      final header = await readRevHeader(source);
      expect(header, isNotNull);
      expect(header!.dataCount, 3);
      expect(header.recCount, 5);
      expect(header.recNum, 3); // Absolute index: DataCount + 0.
      expect(header.totalCount, 8);
      expect(header.eccOffset, 63); // 16 + 47-byte header body.
      expect(header.revCrc, isNot(0));
      expect(header.volumes, hasLength(3));
      expect(header.volumes[0].fileSize, 102400);
      expect(header.volumes[1].fileSize, 102400);
      expect(header.volumes[2].fileSize, 96197);
      expect(source.position(), completion(header.eccOffset));
    });

    test('rejects non-rev data', () async {
      final bytes = await readFile('arc.part1.rar');
      expect(await readRevHeader(MemoryByteSource(bytes)), isNull);
    });
  });

  group('RS16 encoding matches the rev files', () {
    test('re-encodes the ECC stream byte-for-byte', () async {
      final parts = [
        await readFile('arc.part1.rar'),
        await readFile('arc.part2.rar'),
        await readFile('arc.part3.rar'),
      ];
      final maxSize = parts.map((p) => p.length).reduce((a, b) => a > b ? a : b);

      final rs = Rs16();
      expect(rs.init(3, 5), isTrue);
      final outputs = List.generate(5, (_) => Uint8List(maxSize));
      for (var i = 0; i < 3; i++) {
        rs.updateEccAll(i, parts[i], 0, parts[i].length, outputs, 0);
      }

      for (var k = 0; k < 5; k++) {
        final revBytes = await readFile('arc.part${k + 1}.rev');
        final ecc = slice(revBytes, 63, maxSize);
        expect(outputs[k], equals(ecc), reason: 'rev file $k ECC stream');
      }
    });
  });

  group('restoreVolumes', () {
    late List<Uint8List> parts;
    late List<Uint8List> revs;

    setUpAll(() async {
      parts = [
        await readFile('arc.part1.rar'),
        await readFile('arc.part2.rar'),
        await readFile('arc.part3.rar'),
      ];
      revs = [
        for (var k = 0; k < 5; k++) await readFile('arc.part${k + 1}.rev'),
      ];
    });

    Future<List<RevVolume>> makeRevs({List<int>? indices}) async {
      final revVolumes = <RevVolume>[];
      for (final k in indices ?? [0, 1, 2, 3, 4]) {
        final source = MemoryByteSource(revs[k]);
        final header = await readRevHeader(source);
        revVolumes.add(RevVolume(header: header!, source: source));
      }
      return revVolumes;
    }

    Future<Map<int, List<int>>> restore(
      List<Uint8List?> data, {
      required List<RevVolume> revVolumes,
    }) async {
      final chunks = <int, List<int>>{};
      final recovered = await restoreVolumes(
        dataVolumes: [
          for (final d in data)
            d == null ? null : MemoryByteSource(d),
        ],
        revVolumes: revVolumes,
        writeChunk: (index, buffer, length) async {
          (chunks[index] ??= <int>[]).addAll(buffer.sublist(0, length));
        },
      );
      return {for (final i in recovered) i: chunks[i]!};
    }

    test('rebuilds a single missing middle volume', () async {
      final recovered = await restore(
        [parts[0], null, parts[2]],
        revVolumes: await makeRevs(),
      );
      expect(recovered.keys, [1]);
      expect(Uint8List.fromList(recovered[1]!), equals(parts[1]));
    });

    test('rebuilds two missing volumes', () async {
      final recovered = await restore(
        [null, parts[1], null],
        revVolumes: await makeRevs(),
      );
      expect(recovered.keys.toSet(), {0, 2});
      expect(Uint8List.fromList(recovered[0]!), equals(parts[0]));
      expect(Uint8List.fromList(recovered[2]!), equals(parts[2]));
    });

    test('rebuilds the odd-size last volume', () async {
      final recovered = await restore(
        [parts[0], parts[1], null],
        revVolumes: await makeRevs(),
      );
      expect(recovered.keys, [2]);
      expect(recovered[2], hasLength(96197));
      expect(Uint8List.fromList(recovered[2]!), equals(parts[2]));
    });

    test('treats a corrupt volume as missing and repairs it', () async {
      final corrupt = Uint8List.fromList(parts[1]);
      for (var i = 0; i < corrupt.length; i += 97) {
        corrupt[i] ^= 0xff;
      }
      final recovered = await restore(
        [parts[0], corrupt, parts[2]],
        revVolumes: await makeRevs(),
      );
      expect(Uint8List.fromList(recovered[1]!), equals(parts[1]));
    });

    test('reports too many missing volumes', () async {
      final revVolumes = await makeRevs(indices: [0, 1]); // Only 2 valid revs.
      expect(
        () => restore([null, null, null], revVolumes: revVolumes),
        throwsA(isA<UnrarException>()),
      );
    });

    test('rejects a fully-present set', () async {
      expect(
        () async =>
            restore([parts[0], parts[1], parts[2]], revVolumes: await makeRevs()),
        throwsA(isA<UnrarException>()),
      );
    });

    test('rejects recovery volumes from different archives', () async {
      final revVolumes = await makeRevs();
      // Tamper with the data volume list to simulate a mismatched set.
      final header = RevHeader(
        dataCount: 3,
        recCount: 5,
        recNum: 3,
        revCrc: 0,
        volumes: const [
          RevVolumeInfo(fileSize: 1, crc32: 1),
          RevVolumeInfo(fileSize: 1, crc32: 1),
          RevVolumeInfo(fileSize: 1, crc32: 1),
        ],
        eccOffset: 63,
      );
      revVolumes[0] = RevVolume(
        header: header,
        source: MemoryByteSource(revs[0]),
      );
      expect(
        () => restore([null, parts[1], parts[2]], revVolumes: revVolumes),
        throwsA(isA<UnrarException>()),
      );
    });
  });

  group('restoreRevArchive (disk)', () {
    late Directory tmp;

    setUp(() async {
      tmp = await Directory.systemTemp.createTemp('neoasis_rev');
      for (final name in [
        'arc.part1.rar',
        'arc.part2.rar',
        'arc.part3.rar',
        'arc.part1.rev',
        'arc.part2.rev',
        'arc.part3.rev',
        'arc.part4.rev',
        'arc.part5.rev',
      ]) {
        await File('$_dir/$name').copy('${tmp.path}/$name');
      }
    });

    tearDown(() async {
      await tmp.delete(recursive: true);
    });

    test('recreates a deleted volume on disk', () async {
      await File('${tmp.path}/arc.part2.rar').delete();
      final restored =
          await restoreRevArchive('${tmp.path}/arc.part1.rar');
      expect(restored, ['${tmp.path}/arc.part2.rar']);
      final original = await readFile('arc.part2.rar');
      final rebuilt = await File('${tmp.path}/arc.part2.rar').readAsBytes();
      expect(rebuilt, equals(original));
    });

    test('repairs a corrupt volume in place', () async {
      final target = File('${tmp.path}/arc.part3.rar');
      final garbage = Uint8List(96197);
      for (var i = 0; i < garbage.length; i++) {
        garbage[i] = i & 0xff;
      }
      await target.writeAsBytes(garbage, flush: true);
      final restored =
          await restoreRevArchive('${tmp.path}/arc.part3.rar');
      expect(restored, ['${tmp.path}/arc.part3.rar']);
      final original = await readFile('arc.part3.rar');
      expect(await target.readAsBytes(), equals(original));
    });

    test('writes rebuilt volumes to outputDir', () async {
      final out = Directory('${tmp.path}/restored');
      await File('${tmp.path}/arc.part1.rar').delete();
      await restoreRevArchive(
        '${tmp.path}/arc.part2.rar',
        outputDir: out.path,
      );
      final rebuilt = await File('${out.path}/arc.part1.rar').readAsBytes();
      expect(rebuilt, equals(await readFile('arc.part1.rar')));
    });

    test('throws when no valid recovery volume is found', () async {
      await File('${tmp.path}/arc.part1.rar').delete();
      for (var k = 1; k <= 5; k++) {
        await File('${tmp.path}/arc.part$k.rev').delete();
      }
      expect(
        () => restoreRevArchive('${tmp.path}/arc.part2.rar'),
        throwsA(isA<UnrarException>()),
      );
    });
  });
}
