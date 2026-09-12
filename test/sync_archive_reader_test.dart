import 'dart:io';
import 'dart:typed_data';

import 'package:neoasis_unrar/io.dart';
import 'package:neoasis_unrar/neoasis_unrar.dart';
import 'package:test/test.dart';

/// [SyncArchiveReader]/[SyncRarArchive] — the fully synchronous twin of
/// [ArchiveReader]/[RarArchive] added for ISSUE-0059 (gallery_viewer's
/// nested-archive drag-and-drop needs a genuinely synchronous read, and the
/// old workaround spilled bytes to a temp file, which the project's own
/// "no temporary files" rule ruled out).
///
/// Rather than re-derive correctness from scratch, every test here proves
/// the sync path against the *existing*, already-verified async path: same
/// fixture, same entry, same bytes out. A self-contained fixture set (no
/// external corpus dependency) so this suite always runs.
void main() {
  final fixturesDir = '${Directory.current.path}/test/fixtures';

  /// Every entry the async [RarArchive] reports for [fixturePath] is
  /// extracted through both APIs and compared byte-for-byte.
  Future<void> expectSyncMatchesAsync(
    String fixturePath, {
    String? password,
  }) async {
    final asyncArchive = await openRarFile(fixturePath, password: password);
    addTearDown(asyncArchive.close);
    final entries = await asyncArchive.list();

    final sync = SyncRarArchive.openBytes(
      File(fixturePath).readAsBytesSync(),
      password: password,
    );
    addTearDown(sync.close);

    expect(
      sync.list().map((e) => e.name).toList(),
      entries.map((e) => e.name).toList(),
      reason: 'sync.list() should report the same entries in the same '
          'order as the async reader',
    );

    for (final entry in entries) {
      if (entry.isDirectory) continue;
      final asyncBytes = await asyncArchive.extractFile(entry.name);
      final syncBytes = sync.extractFile(entry.name);
      expect(syncBytes, isNotNull, reason: '${entry.name} (sync)');
      expect(
        syncBytes,
        equals(asyncBytes),
        reason: '${entry.name}: sync and async extraction disagree',
      );
    }
  }

  group('SyncRarArchive matches RarArchive byte-for-byte', () {
    // Plain, unencrypted fixtures spanning RAR 4.x and 5.0, stored and
    // compressed entries, comments/protect/signed flags, VM-filter
    // compression (delta/RGB/audio/x86 chains), symlinks, hardlinks, and
    // BLAKE2sp-hashed entries.
    for (final name in [
      'rar4_comment.rar',
      'rar4_protected.rar',
      'rar4_signed.rar',
      'rar4_vmfilter_ls.rar',
      'rar4_vmfilter_delta.rar',
      'rar4_vmfilter_rgb.rar',
      'rar4_vmfilter_audio.rar',
      'rar4_vmfilter_chain.rar',
      'rar4_exttime.rar',
      'symlinks.rar',
      'hardlink.rar',
      'with_htime.rar',
      'with_owner.rar',
      'blake2.rar',
    ]) {
      test(name, () => expectSyncMatchesAsync('$fixturesDir/$name'));
    }

    // Encrypted fixtures (RAR 4.x AES-128 and RAR 5.0 AES-256, plain CRC32
    // and HMAC-keyed CRC32/BLAKE2 MAC variants).
    test(
      'rar4_encrypted.rar',
      () => expectSyncMatchesAsync(
        '$fixturesDir/rar4_encrypted.rar',
        password: 'test123',
      ),
    );
    test(
      'rar4_longpwd.rar',
      () => expectSyncMatchesAsync(
        '$fixturesDir/rar4_longpwd.rar',
        password: 'correct horse battery staple across many blocks '
            '0123456789',
      ),
    );
    test(
      'enc_store.rar',
      () => expectSyncMatchesAsync(
        '$fixturesDir/enc_store.rar',
        password: 'test123',
      ),
    );
    test(
      'blake2_enc.rar',
      () => expectSyncMatchesAsync(
        '$fixturesDir/blake2_enc.rar',
        password: 'testpass',
      ),
    );
  });

  group('SyncRarArchive error handling', () {
    test('wrong password throws UnrarException, matching the async reader',
        () {
      final bytes =
          File('$fixturesDir/rar4_encrypted.rar').readAsBytesSync();
      final archive =
          SyncRarArchive.openBytes(bytes, password: 'wrongpassword');
      addTearDown(archive.close);
      final entries = archive.list();
      expect(
        () => archive.extractFile(entries.single.name),
        throwsA(isA<UnrarException>()),
      );
    });

    test('a nonexistent entry name returns null', () {
      final bytes = File('$fixturesDir/hardlink.rar').readAsBytesSync();
      final archive = SyncRarArchive.openBytes(bytes);
      addTearDown(archive.close);
      expect(archive.extractFile('no-such-entry.bin'), isNull);
    });

    test(
      'a multi-volume archive throws UnrarException on the split entry '
      "rather than silently truncating — SyncArchiveReader's documented "
      'scope cut',
      () {
        final bytes =
            File('$fixturesDir/vol.part1.rar').readAsBytesSync();
        final archive = SyncRarArchive.openBytes(bytes);
        addTearDown(archive.close);
        final entries = archive.list();
        expect(
          () => archive.extractFile(entries.single.name),
          throwsA(isA<UnrarException>()),
        );
      },
    );
  });

  group('SyncByteSource / MemorySyncByteSource', () {
    test('read/seek/position/length mirror MemoryByteSource semantics', () {
      final source = MemorySyncByteSource(
        Uint8List.fromList([1, 2, 3, 4, 5]),
      );
      expect(source.length(), 5);
      expect(source.position(), 0);
      expect(source.read(2), [1, 2]);
      expect(source.position(), 2);
      source.seek(4);
      expect(source.read(10), [5]);
      expect(source.read(1), isEmpty);
    });
  });
}
