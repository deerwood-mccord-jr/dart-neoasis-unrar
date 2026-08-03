import 'dart:io';

import 'package:neoasis_unrar/io.dart';
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:test/test.dart';

/// Integration tests against real archives in the sibling `dart_unrar`
/// repository (`../dart_unrar/test_data` and `test/fixtures`).
///
/// Ground truth (entry names in archive order, unpacked/compressed sizes,
/// directory markers) was captured with `unrar lb` / `unrar lt` 7.x. The
/// whole suite is skipped when the `dart_unrar` checkout is not present.
void main() {
  final corpus = _corpusRoot();
  if (corpus == null) {
    test('real archive corpus not found', () {}, skip: 'dart_unrar repo absent');
    return;
  }

  group('real archives (dart_unrar corpus)', () {
    for (final c in _cases) {
      test('${c.label} lists entries matching unrar', () async {
        final archive = await openRarFile(_path(c.path));
        addTearDown(archive.close);
        final entries = await archive.list();
        expect(entries, hasLength(c.expected.length));
        for (var i = 0; i < c.expected.length; i++) {
          final exp = c.expected[i];
          final act = entries[i];
          expect(
            c.suffixOnly ? act.name.endsWith(exp.name) : act.name == exp.name,
            isTrue,
            reason: 'entry $i name: expected ${exp.name}, got ${act.name}',
          );
          expect(act.isDirectory, exp.isDir, reason: 'entry $i ${exp.name}');
          if (!exp.isDir) {
            expect(act.unpSize, exp.size, reason: 'entry $i ${exp.name} size');
            expect(act.packSize, exp.pack,
                reason: 'entry $i ${exp.name} packed size');
          }
        }
      });
    }

    test('multi.part01.rar reads the stored header faithfully', () async {
      // This corpus archive stores a main header with no volume flag and a
      // file header with no split flags (both CRC-valid), so we assert that
      // it is read exactly as stored. Real volume flags are covered by the
      // self-contained test/fixtures/vol.part*.rar group below.
      final archive = await openRarFile(_path('test_data/multi.part01.rar'));
      addTearDown(archive.close);
      expect(archive.info.volume, isFalse);
      expect(archive.info.firstVolume, isFalse);
      final entries = await archive.list();
      expect(entries.single.packSize, 145);
      expect(entries.single.unpSize, 3000);
      expect(entries.single.splitAfter, isFalse);
    });

    test('encrypted_data.rar lists with entries flagged encrypted', () async {
      final archive = await openRarFile(_path('test_data/encrypted_data.rar'));
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, isNotEmpty);
      expect(entries.every((e) => e.isEncrypted), isTrue);
    });

    test('encrypted_headers.rar throws on open without a password', () async {
      await expectLater(
        openRarFile(_path('test_data/encrypted_headers.rar')),
        throwsA(isA<UnrarException>()),
      );
    });
  });

  group('real volume fixtures (rar 7.x output)', () {
    const cases = <String, Map<String, Object>>{
      'vol.part1.rar': {
        'volume': true,
        'firstVolume': true,
        'splitBefore': false,
        'splitAfter': true,
      },
      'vol.part2.rar': {
        'volume': true,
        'firstVolume': false,
        'splitBefore': true,
        'splitAfter': true,
      },
      'vol.part3.rar': {
        'volume': true,
        'firstVolume': false,
        'splitBefore': true,
        'splitAfter': true,
      },
      'vol.part4.rar': {
        'volume': true,
        'firstVolume': false,
        'splitBefore': true,
        'splitAfter': false,
      },
    };

    cases.forEach((file, expected) {
      test('$file reports volume and split flags', () async {
        final archive = await openRarFile(
            '${Directory.current.path}/test/fixtures/$file');
        addTearDown(archive.close);
        expect(archive.info.volume, expected['volume']);
        expect(archive.info.firstVolume, expected['firstVolume']);
        final entries = await archive.list();
        expect(entries, hasLength(1));
        expect(entries.single.name, 'data.bin');
        expect(entries.single.unpSize, 5000);
        expect(entries.single.splitBefore, expected['splitBefore']);
        expect(entries.single.splitAfter, expected['splitAfter']);
      });
    });
  });
}

class _Expected {
  const _Expected(this.name,
      {this.size, this.pack, this.isDir = false});

  final String name;
  final int? size;
  final int? pack;
  final bool isDir;
}

class _Case {
  const _Case(this.label, this.path, this.expected,
      {this.suffixOnly = false});

  final String label;
  final String path;
  final List<_Expected> expected;

  /// When true, entry names are only matched by suffix (archives created
  /// without `-ep1` store absolute source paths).
  final bool suffixOnly;
}

String _path(String rel) => '${_corpusRoot()!.path}/$rel';

Directory? _corpusRoot() {
  final cwd = Directory.current;
  final candidates = [
    Directory('${cwd.path}/../dart_unrar'),
    Directory('${cwd.path}/dart_unrar'),
  ];
  for (final d in candidates) {
    if (File('${d.path}/test_data/basic_rar5.rar').existsSync()) {
      return d;
    }
  }
  return null;
}

final _cases = <_Case>[
  _Case(
    'test/fixtures/test.rar',
    'test/fixtures/test.rar',
    const [
      _Expected('test.txt', size: 104, pack: 101),
      _Expected('file2.txt', size: 18, pack: 18),
    ],
  ),
  _Case(
    'basic_rar4',
    'test_data/basic_rar4.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 147),
      _Expected('world.txt', size: 141, pack: 141),
    ],
  ),
  _Case(
    'basic_rar5',
    'test_data/basic_rar5.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 131),
      _Expected('world.txt', size: 141, pack: 128),
    ],
    suffixOnly: true,
  ),
  _Case(
    'binary (stored)',
    'test_data/binary.rar',
    const [_Expected('binary.bin', size: 512, pack: 512)],
    suffixOnly: true,
  ),
  _Case(
    'encrypted_data',
    'test_data/encrypted_data.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 144),
      _Expected('world.txt', size: 141, pack: 128),
    ],
    suffixOnly: true,
  ),
  _Case(
    'multi-volume first part',
    'test_data/multi.part01.rar',
    const [_Expected('large_for_split.txt', size: 3000, pack: 145)],
    suffixOnly: true,
  ),
  _Case(
    'rar4 binary',
    'test_data/rar4_binary.rar',
    const [_Expected('binary.bin', size: 512, pack: 512)],
  ),
  _Case(
    'rar4 solid',
    'test_data/rar4_solid.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 147),
      _Expected('world.txt', size: 141, pack: 141),
      _Expected('subdir/nested.txt', size: 125, pack: 125),
    ],
  ),
  _Case(
    'rar4 with dirs',
    'test_data/rar4_with_dirs.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 147),
      _Expected('world.txt', size: 141, pack: 141),
      _Expected('subdir', isDir: true),
      _Expected('subdir/nested.txt', size: 125, pack: 125),
    ],
  ),
  _Case(
    'solid',
    'test_data/solid.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 154),
      _Expected('nested.txt', size: 125, pack: 63),
      _Expected('world.txt', size: 141, pack: 70),
    ],
  ),
  _Case(
    'unicode names',
    'test_data/unicode_names.rar',
    const [_Expected('café.txt', size: 49, pack: 49)],
    suffixOnly: true,
  ),
  _Case(
    'with dirs (rar5)',
    'test_data/with_dirs.rar',
    const [
      _Expected('hello.txt', size: 147, pack: 131),
      _Expected('world.txt', size: 141, pack: 128),
      _Expected('nested.txt', size: 125, pack: 111),
      _Expected('subdir', isDir: true),
    ],
  ),
];
