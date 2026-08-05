import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/io.dart';
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:neoasis_unrar/src/blake2s.dart';
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

  group('real extraction (stored archives)', () {
    // Fully stored (method 0) archives whose unpacked bytes must exactly
    // match the source files they were created from.
    const storedCases = <String, List<String>>{
      'test_data/basic_rar4.rar': ['hello.txt', 'world.txt'],
      'test_data/binary.rar': ['binary.bin'],
      'test_data/rar4_binary.rar': ['binary.bin'],
      'test_data/rar4_solid.rar': ['hello.txt', 'world.txt', 'nested.txt'],
      'test_data/rar4_with_dirs.rar': ['hello.txt', 'world.txt', 'nested.txt'],
      'test_data/unicode_names.rar': ['café.txt'],
    };

    storedCases.forEach((path, expectedNames) {
      test('${path.split('/').last} extracts byte-exact files', () async {
        final archive = await openRarFile(_path(path));
        addTearDown(archive.close);

        final extracted = <String, List<int>>{};
        await archive.extractAll((entry, data) {
          extracted[entry.name.split('/').last] = data;
        });

        expect(extracted.keys.toSet(), expectedNames.toSet());
        for (final name in expectedNames) {
          final ref = File(_sourceFor(name)).readAsBytesSync();
          expect(extracted[name], ref, reason: '$name does not match source');
        }
      });
    });

    test('extractFile returns byte-exact data and works after list()',
        () async {
      final archive = await openRarFile(_path('test_data/basic_rar4.rar'));
      addTearDown(archive.close);

      await archive.list();
      final hello = await archive.extractFile('hello.txt');
      expect(hello, File(_sourceFor('hello.txt')).readAsBytesSync());

      final missing = await archive.extractFile('nope.txt');
      expect(missing, isNull);
    });

    test('extractFile seeks straight to the data in solid archives', () async {
      final archive = await openRarFile(_path('test_data/rar4_solid.rar'));
      addTearDown(archive.close);
      final nested = await archive.extractFile('subdir/nested.txt');
      expect(nested, File(_sourceFor('nested.txt')).readAsBytesSync());
    });

    test('testArchive passes for fully stored archives', () async {
      final archive = await openRarFile(_path('test_data/basic_rar4.rar'));
      addTearDown(archive.close);
      expect(await archive.testArchive(), isTrue);
    });

    test('encrypted file data throws an UnrarException', () async {
      final archive = await openRarFile(_path('test_data/encrypted_data.rar'));
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries.first.isEncrypted, isTrue);
      await expectLater(
        archive.extractFile(entries.first.name),
        throwsA(isA<UnrarException>()),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // M6 Encryption tests
  // ---------------------------------------------------------------------------

  group('RAR 5.0 data encryption (encrypted_data.rar)', () {
    // The corpus fixture has two compressed+encrypted files created by
    // `rar a -ptest123`. Password check and HMAC-SHA256 MAC are both present.
    const password = 'test123';
    const archivePath = 'test_data/encrypted_data.rar';

    test('wrong password throws UnrarException', () async {
      final archive =
          await openRarFile(_path(archivePath), password: 'wrong');
      addTearDown(archive.close);
      final entries = await archive.list();
      await expectLater(
        archive.extractFile(entries.first.name),
        throwsA(isA<UnrarException>()),
      );
    });

    test('extracts hello.txt byte-exact with correct password', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      final hello = await archive
          .extractFile('Users/dmccordjr/DevProjects/flutterprojects/'
              'dart_unrar/test_data/sources/hello.txt');
      expect(hello, isNotNull);
      expect(
          hello,
          File(_sourceFor('hello.txt')).readAsBytesSync(),
          reason: 'hello.txt content mismatch');
    });

    test('extractAll extracts both files byte-exact', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      final extracted = <String, List<int>>{};
      await archive.extractAll((entry, data) {
        extracted[entry.name.split('/').last] = data;
      });
      expect(extracted.keys.toSet(), {'hello.txt', 'world.txt'});
      for (final name in ['hello.txt', 'world.txt']) {
        expect(extracted[name], File(_sourceFor(name)).readAsBytesSync(),
            reason: '$name content mismatch');
      }
    });

    test('testArchive passes with correct password', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      expect(await archive.testArchive(), isTrue);
    });
  });

  group('RAR 5.0 header encryption (encrypted_headers.rar)', () {
    // Created with `rar a -hp test123`. All headers are encrypted; the
    // data uses plain CRC32 (no HASHMAC flag).
    const password = 'test123';
    const archivePath = 'test_data/encrypted_headers.rar';

    test('opens successfully with correct password', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(2));
      expect(entries.every((e) => e.isEncrypted), isTrue);
      expect(entries[0].unpSize, 147);
      expect(entries[1].unpSize, 141);
    });

    test('throws wrong password on bad password', () async {
      await expectLater(
        openRarFile(_path(archivePath), password: 'wrong'),
        throwsA(isA<UnrarException>()),
      );
    });

    test('extractAll extracts both files byte-exact', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      final extracted = <String, List<int>>{};
      await archive.extractAll((entry, data) {
        extracted[entry.name.split('/').last] = data;
      });
      expect(extracted.keys.toSet(), {'hello.txt', 'world.txt'});
      for (final name in ['hello.txt', 'world.txt']) {
        expect(extracted[name], File(_sourceFor(name)).readAsBytesSync(),
            reason: '$name content mismatch');
      }
    });

    test('testArchive passes', () async {
      final archive =
          await openRarFile(_path(archivePath), password: password);
      addTearDown(archive.close);
      expect(await archive.testArchive(), isTrue);
    });
  });

  group('RAR 5.0 stored + encrypted (fixture enc_store.rar)', () {
    // Method-0 (store) archive with encryption. The decrypted payload is
    // just the raw plaintext + zero padding; no decompressor needed.
    final fixturePath =
        '${Directory.current.path}/test/fixtures/enc_store.rar';
    const password = 'test123';
    const expectedContent = 'hello world 0123456789\n';

    test('extracts stored file byte-exact', () async {
      final archive = await openRarFile(fixturePath, password: password);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      final data = await archive.extractFile(entries.single.name);
      expect(data, isNotNull);
      expect(String.fromCharCodes(data!), expectedContent);
    });
  });

  group('RAR 4.x data encryption (crafted fixtures)', () {
    // Fixtures were crafted at the binary level by make_rar4_enc.py /
    // make_rar4_long.py using our kdf3 implementation. The CRC32 stored in
    // the file header was computed from the plaintext by the same scripts,
    // so our kdf3 + AES-128-CBC correctly reproduces the decrypted content.
    final fixturesDir = '${Directory.current.path}/test/fixtures';

    test('rar4_encrypted.rar extracts stored file with password test123',
        () async {
      final archive = await openRarFile(
          '$fixturesDir/rar4_encrypted.rar',
          password: 'test123');
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      expect(entries.single.isEncrypted, isTrue);
      // The plaintext is 'hello world, this is a secret message\n' * 3.
      final data = await archive.extractFile(entries.single.name);
      expect(data, isNotNull);
      expect(
          String.fromCharCodes(data!),
          'hello world, this is a secret message\n' * 3);
    });

    test('rar4_longpwd.rar extracts with the long password', () async {
      const longPwd =
          'correct horse battery staple across many blocks 0123456789';
      final archive = await openRarFile(
          '$fixturesDir/rar4_longpwd.rar',
          password: longPwd);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      expect(entries.single.isEncrypted, isTrue);
      final data = await archive.extractFile(entries.single.name);
      expect(data, isNotNull);
      expect(data!.length, greaterThan(0));
      expect(
          String.fromCharCodes(data),
          'long password test payload for rar29 mutation path\n' * 3);
    });

    test('wrong password throws UnrarException', () async {
      final archive = await openRarFile(
          '$fixturesDir/rar4_encrypted.rar',
          password: 'wrongpwd');
      addTearDown(archive.close);
      final entries = await archive.list();
      await expectLater(
        archive.extractFile(entries.single.name),
        throwsA(isA<UnrarException>()),
      );
    });
  });

  group('real extraction (RAR 5 compressed)', () {
    // RAR 5.0 method 3 (deflate-style LZ) archives whose unpacked bytes must
    // exactly match the source files. solid.rar additionally exercises window
    // state carry-over across the files of a solid stream.
    const compressedCases = <String, List<String>>{
      'test_data/basic_rar5.rar': ['hello.txt', 'world.txt'],
      'test_data/with_dirs.rar': ['hello.txt', 'world.txt', 'nested.txt'],
      'test_data/solid.rar': ['hello.txt', 'nested.txt', 'world.txt'],
    };

    compressedCases.forEach((path, expectedNames) {
      test('${path.split('/').last} extracts byte-exact RAR5 files', () async {
        final archive = await openRarFile(_path(path));
        addTearDown(archive.close);

        final extracted = <String, List<int>>{};
        await archive.extractAll((entry, data) {
          extracted[entry.name.split('/').last] = data;
        });

        expect(extracted.keys.toSet(), expectedNames.toSet());
        for (final name in expectedNames) {
          final ref = File(_sourceFor(name)).readAsBytesSync();
          expect(extracted[name], ref, reason: '$name does not match source');
        }
      });
    });

    test('extractFile unpacks the solid stream before a later file', () async {
      final archive = await openRarFile(_path('test_data/solid.rar'));
      addTearDown(archive.close);
      final world = await archive.extractFile('world.txt');
      expect(world, File(_sourceFor('world.txt')).readAsBytesSync());
    });

    test('testArchive passes for compressed RAR5 archives', () async {
      final archive = await openRarFile(_path('test_data/basic_rar5.rar'));
      addTearDown(archive.close);
      expect(await archive.testArchive(), isTrue);
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

  // ---------------------------------------------------------------------------
  // M7: Multi-volume extraction
  // ---------------------------------------------------------------------------

  group('multi-volume extraction (vol.part*.rar)', () {
    final fixturesDir = '${Directory.current.path}/test/fixtures';
    final part1 = '$fixturesDir/vol.part1.rar';

    test('nextVolumeName computes correct names for new-style numbering', () {
      expect(nextVolumeName('vol.part1.rar'), 'vol.part2.rar');
      expect(nextVolumeName('vol.part9.rar'), 'vol.part10.rar');
      expect(nextVolumeName('vol.part99.rar'), 'vol.part100.rar');
      expect(nextVolumeName('archive.part001.rar'), 'archive.part002.rar');
    });

    test('nextVolumeName computes correct names for old-style numbering', () {
      expect(nextVolumeName('archive.rar', oldNumbering: true), 'archive.r00');
      expect(nextVolumeName('archive.r00', oldNumbering: true), 'archive.r01');
      expect(nextVolumeName('archive.r99', oldNumbering: true), 'archive.s00');
    });

    test('openRarFile auto-chains volumes and extracts data.bin byte-exact',
        () async {
      // Verify with the reference unrar output extracted to /tmp/vol_test.
      final reference = File('/tmp/vol_test/data.bin');
      if (!reference.existsSync()) {
        markTestSkipped('Reference file /tmp/vol_test/data.bin not present; '
            'run: unrar e ${Directory.current.path}/test/fixtures/vol.part1.rar /tmp/vol_test/');
        return;
      }
      final archive = await openRarFile(part1);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      expect(entries.single.name, 'data.bin');
      expect(entries.single.unpSize, 5000);
      final data = await archive.extractFile('data.bin');
      expect(data, isNotNull);
      expect(data!.length, 5000);
      expect(data, reference.readAsBytesSync(),
          reason: 'data.bin content mismatch across volumes');
    });

    test('extractAll assembles all 5000 bytes from four volumes', () async {
      final reference = File('/tmp/vol_test/data.bin');
      if (!reference.existsSync()) {
        markTestSkipped('Reference /tmp/vol_test/data.bin not present');
        return;
      }
      final archive = await openRarFile(part1);
      addTearDown(archive.close);
      Uint8List? result;
      await archive.extractAll((entry, data) {
        if (entry.name == 'data.bin') result = data;
      });
      expect(result, isNotNull);
      expect(result!.length, 5000);
      expect(result, reference.readAsBytesSync(),
          reason: 'data.bin content mismatch from extractAll');
    });

    test('missing resolver throws UnrarException for split entries', () async {
      // Open without auto-volume support.
      final archive = await openRarFile(part1, autoVolume: false);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries.single.splitAfter, isTrue);
      await expectLater(
        archive.extractFile('data.bin'),
        throwsA(isA<UnrarException>()),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // M8: Extra field parsing (FHEXTRA_REDIR, FHEXTRA_UOWNER, FHEXTRA_HTIME)
  // ---------------------------------------------------------------------------

  group('M8: FHEXTRA_REDIR – symlinks and redirections', () {
    final fixturePath =
        '${Directory.current.path}/test/fixtures/symlinks.rar';

    test('symlink entry has redirectType=fsRedirUnixSymlink', () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      final link =
          entries.firstWhere((e) => e.name.endsWith('mylink.txt'));
      expect(link.redirectType, FileSystemRedirect.fsRedirUnixSymlink);
      expect(link.redirectTarget, 'target.txt');
      expect(link.isRedirect, isTrue);
    });

    test('regular file has no redirect', () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      final file =
          entries.firstWhere((e) => e.name.endsWith('target.txt'));
      expect(file.redirectType, FileSystemRedirect.fsRedirNone);
      expect(file.redirectTarget, isNull);
      expect(file.isRedirect, isFalse);
    });

    test('RAR 4.x Unix symlink detected from fileAttr', () async {
      // rar4_lz_normal.rar contains a testlink entry with Unix symlink attrs.
      final fixturePath4x =
          '${Directory.current.path}/test/fixtures/libarchive/rar4_lz_normal.rar';
      final archive = await openRarFile(fixturePath4x);
      addTearDown(archive.close);
      final entries = await archive.list();
      final link = entries.firstWhere((e) => e.name == 'testlink',
          orElse: () => throw StateError('testlink not found'));
      expect(link.redirectType, FileSystemRedirect.fsRedirUnixSymlink);
    });
  });

  group('M8: FHEXTRA_UOWNER – Unix owner/group', () {
    final fixturePath =
        '${Directory.current.path}/test/fixtures/with_owner.rar';

    test('entry has unixOwner with numeric uid and gid', () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      final entry = entries.single;
      expect(entry.unixOwner, isNotNull);
      expect(entry.unixOwner!.ownerId, isNotNull);
      expect(entry.unixOwner!.groupId, isNotNull);
    });
  });

  group('M8: FHEXTRA_HTIME – high-precision timestamps', () {
    final fixturePath =
        '${Directory.current.path}/test/fixtures/with_htime.rar';

    test('entry has modifiedTime from FHEXTRA_HTIME', () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(1));
      // The file was touched to 2026-01-01; the FHEXTRA_HTIME record should
      // carry a timestamp from that day.
      final e = entries.single;
      expect(e.modifiedTime, isNotNull);
    });
  });

  group('M8: RAR 4.x corpus extra metadata', () {
    test('rar4_lz_normal.rar: listing includes symlink, dirs and files',
        () async {
      final fixturePath =
          '${Directory.current.path}/test/fixtures/libarchive/rar4_lz_normal.rar';
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries.any((e) => e.isDirectory), isTrue,
          reason: 'should have directory entries');
      expect(entries.any((e) => e.isRedirect), isTrue,
          reason: 'should have symlink entry');
    });
  });

  // ---------------------------------------------------------------------------
  // M9: FHEXTRA_HASH – BLAKE2sp file hashes (-htb archives)
  // ---------------------------------------------------------------------------

  group('M9: BLAKE2sp file hashes (blake2.rar)', () {
    final fixturePath = '${Directory.current.path}/test/fixtures/blake2.rar';
    final refDir = '${Directory.current.path}/test/fixtures/blake2_ref';

    test('entries expose hashType=blake2 and a 32-byte digest', () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(2));
      for (final e in entries) {
        expect(e.hashType, FileHashType.blake2,
            reason: '${e.name} should carry a BLAKE2 hash');
        expect(e.blake2Digest, isNotNull);
        expect(e.blake2Digest!.length, 32);
      }
    });

    test('entries without -htb have no hash', () async {
      // enc_store.rar was created without -htb, so no FHEXTRA_HASH record.
      final plain = await openRarFile(
          '${Directory.current.path}/test/fixtures/enc_store.rar');
      addTearDown(plain.close);
      final e = (await plain.list()).single;
      expect(e.hashType, FileHashType.none);
      expect(e.blake2Digest, isNull);
    });

    test('extractAll produces byte-exact data matching the reference files',
        () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final extracted = <String, List<int>>{};
      await archive.extractAll((entry, data) {
        extracted[entry.name.split('/').last] = data;
      });
      expect(extracted.keys.toSet(), {'fox.txt', 'blob.bin'});
      for (final name in ['fox.txt', 'blob.bin']) {
        final ref = File('$refDir/$name').readAsBytesSync();
        expect(extracted[name], ref, reason: '$name does not match reference');
      }
    });

    test('stored digest matches the digest computed from the reference file',
        () async {
      final archive = await openRarFile(fixturePath);
      addTearDown(archive.close);
      final entries = await archive.list();
      for (final e in entries) {
        final ref = File('$refDir/${e.name.split('/').last}').readAsBytesSync();
        expect(_hex(e.blake2Digest!), _hex(Blake2Sp.digest(ref)),
            reason: '${e.name} stored digest should equal BLAKE2sp(ref)');
      }
    });
  });

  group('M9: BLAKE2 MAC verification (blake2_enc.rar)', () {
    final fixturePath =
        '${Directory.current.path}/test/fixtures/blake2_enc.rar';
    final refDir = '${Directory.current.path}/test/fixtures/blake2_ref';
    const password = 'testpass';

    test('encrypted entries extract byte-exact with the correct password',
        () async {
      final archive = await openRarFile(fixturePath, password: password);
      addTearDown(archive.close);
      final entries = await archive.list();
      expect(entries, hasLength(2));
      expect(entries.every((e) => e.isEncrypted), isTrue);
      for (final e in entries) {
        expect(e.hashType, FileHashType.blake2);
        expect(e.blake2Digest!.length, 32);
      }
      final extracted = <String, List<int>>{};
      await archive.extractAll((entry, data) {
        extracted[entry.name.split('/').last] = data;
      });
      for (final name in ['fox.txt', 'blob.bin']) {
        final ref = File('$refDir/$name').readAsBytesSync();
        expect(extracted[name], ref, reason: '$name does not match reference');
      }
    });

    test('wrong password fails BLAKE2 MAC verification', () async {
      final archive = await openRarFile(fixturePath, password: 'wrongpass');
      addTearDown(archive.close);
      final entries = await archive.list();
      await expectLater(
        archive.extractFile(entries.first.name),
        throwsA(isA<UnrarException>()),
      );
    });
  });
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

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

/// Maps the base name of an extracted entry to its source file inside the
/// `dart_unrar/test_data` tree.
String _sourceFor(String name) {
  final root = _corpusRoot()!;
  if (name == 'nested.txt') {
    return '${root.path}/test_data/sources/subdir/nested.txt';
  }
  return '${root.path}/test_data/sources/$name';
}

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

// ---------------------------------------------------------------------------
// M7 volume chaining tests (added at end of file)
