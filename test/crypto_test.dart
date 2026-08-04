import 'package:neoasis_unrar/src/aes.dart';
import 'package:neoasis_unrar/src/hmac.dart';
import 'package:neoasis_unrar/src/kdf3.dart';
import 'package:neoasis_unrar/src/kdf5.dart';
import 'package:neoasis_unrar/src/sha1.dart';
import 'package:neoasis_unrar/src/sha256.dart';
import 'package:test/test.dart';

import 'crypto_vectors.dart';

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('sha1', () {
    test('standard vectors', () {
      sha1Vectors.forEach((name, expected) {
        expect(hex(sha1Bytes(_text(shaMessages[name]!))), expected);
      });
    });

    test('rar29 equals standard for single-block input', () {
      // For messages <= 64 bytes the write-back never triggers, so the
      // variant must equal standard SHA-1.
      final raw = _utf16le('test123')..addAll(hx('0102030405060708'));
      final copy = List<int>.of(raw);
      final ctx = Sha1Context();
      sha1ProcessRar29(ctx, raw);
      expect(hex(sha1Bytes(copy)), hex(sha1Bytes(raw)));
    });

    test('rar29 mutates multi-block input', () {
      // A 3-block message: the block after the buffered first is rewritten in
      // place, so the rar29 digest differs from standard SHA-1 of the same
      // message, and the input buffer itself is mutated.
      final msg = List<int>.filled(160, 0x61);
      final copy = List<int>.of(msg);
      final ctx = Sha1Context();
      sha1ProcessRar29(ctx, msg);
      expect(hex(sha1Bytes(copy)), isNot(hex(sha1Bytes(msg))));
    });
  });

  group('sha256', () {
    test('standard vectors', () {
      sha256Vectors.forEach((name, expected) {
        expect(hex(sha256(_text(shaMessages[name]!))), expected);
      });
    });
  });

  group('hmac-sha256', () {
    test('RFC 4231 vectors', () {
      final cases = <List<int>>[
        hx('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
        _text('what do ya want for nothing?'),
      ];
      expect(hex(hmacSha256(hx('0b' * 20), _text('Hi There'))), hmacVectors['rfc1']);
      expect(hex(hmacSha256(_text('Jefe'), cases[1])), hmacVectors['rfc2']);
      final data3 = List<int>.generate(50, (i) => i);
      expect(hex(hmacSha256(hx('aa' * 20), data3)), hmacVectors['rfc3']);
      expect(hex(hmacSha256(hx('aa' * 32), _text('data'))), hmacVectors['k32']);
    });
  });

  group('kdf5 (RAR5 / PBKDF2)', () {
    test('continuous chain matches embedded C test vectors', () {
      final c1 = kdf5('password', _text('salt'), 0); // 2^0 = 1 iteration
      expect(hex(c1.key), pbkdf2Vectors['c1']!['key']);
      expect(hex(c1.hashKey), pbkdf2Vectors['c1']!['v1']);
      expect(hex(c1.pswCheckValue), pbkdf2Vectors['c1']!['v2']);

      final c4096 = kdf5('password', _text('salt'), 12); // 2^12 = 4096
      expect(hex(c4096.key), pbkdf2Vectors['c4096']!['key']);
      expect(hex(c4096.hashKey), pbkdf2Vectors['c4096']!['v1']);
      expect(hex(c4096.pswCheckValue), pbkdf2Vectors['c4096']!['v2']);
    });

    test('real encrypted_data.rar fixture', () {
      final k = kdf5(
          'test123', hx(rar5DataVectors['salt'] as String), rar5DataVectors['lg2'] as int);
      expect(hex(k.key), rar5DataVectors['key']);
      expect(hex(k.hashKey), rar5DataVectors['hashKey']);
      expect(hex(k.pswCheckValue), rar5DataVectors['pswValue']);
      expect(hex(foldPswCheck(k.pswCheckValue)), rar5DataVectors['fold']);
      expect(rar5DataVectors['fold'], rar5DataVectors['stored']);
    });

    test('real encrypted_headers.rar fixture', () {
      final k = kdf5('test123', hx(rar5HeadersVectors['salt'] as String),
          rar5HeadersVectors['lg2'] as int);
      expect(hex(foldPswCheck(k.pswCheckValue)), rar5HeadersVectors['fold']);
      expect(rar5HeadersVectors['fold'], rar5HeadersVectors['stored']);
    });

    test('crc32-mac matches stored MACs of encrypted_data.rar', () {
      // hello.txt: plain CRC 8bc459b5 -> MAC 55c560e3
      final k = kdf5(
          'test123', hx(rar5DataVectors['salt'] as String), rar5DataVectors['lg2'] as int);
      expect(
          crc32Mac(hx('b559c48b'), k.hashKey).toRadixString(16).padLeft(8, '0'),
          '55c560e3');
      // world.txt: plain CRC 2a8d18f9 -> MAC 42ce6a19
      expect(
          crc32Mac(hx('f9188d2a'), k.hashKey).toRadixString(16).padLeft(8, '0'),
          '42ce6a19');
    });
  });

  group('kdf3 (RAR3 / RAR4)', () {
    test('rar3-comment-psw.rar fixture', () {
      final r = kdf3(rar3Fixture['password'] as String,
          hx(rar3Fixture['salt'] as String));
      expect(hex(r.key), (rar3Fixture['kdf3'] as List)[0]);
      expect(hex(r.init), (rar3Fixture['kdf3'] as List)[1]);
    });

    test('crafted rar4 fixture', () {
      final r = kdf3(rar4Crafted['password'] as String,
          hx(rar4Crafted['salt'] as String));
      expect(hex(r.key), (rar4Crafted['kdf3'] as List)[0]);
      expect(hex(r.init), (rar4Crafted['kdf3'] as List)[1]);
    });

    test('long password exercises the rar29 mutation path', () {
      // 58 chars -> 124 raw bytes (multi-block); validated byte-exact by
      // `unrar x -p<password>` against a crafted RAR4 fixture.
      const password =
          'correct horse battery staple across many blocks 0123456789';
      final r = kdf3(password, hx('0102030405060708'));
      expect(hex(r.key), '486450997201169c00484172789fd6f8');
      expect(hex(r.init), '7ffd6a2245b4e1f7a547854f8ae50178');
      // A standard-SHA-1 KDF3 would give 209207ce...; the rar29 variant
      // differs, so the mutation path is what unrar implements.
      expect(hex(r.key), isNot('209207ceebc57e6dba1728ea3697984bffd30743'));
    });
  });

  group('aes', () {
    test('cbc decrypt/encrypt round trip 128', () {
      final aes = Aes.withKey(hx(aes128Vectors['key'] as String));
      final ct = hx(aes128Vectors['ct'] as String);
      final pt = List<int>.of(hx(aes128Vectors['pt'] as String));
      final d = AesCbcDecryptor(aes, hx(aes128Vectors['iv'] as String));
      expect(hex(d.decrypt(ct)), hex(pt));
    });

    test('cbc decrypt/encrypt round trip 256', () {
      final aes = Aes.withKey(hx(aes256Vectors['key'] as String));
      final ct = hx(aes256Vectors['ct'] as String);
      final pt = List<int>.of(hx(aes256Vectors['pt'] as String));
      final d = AesCbcDecryptor(aes, hx(aes256Vectors['iv'] as String));
      expect(hex(d.decrypt(ct)), hex(pt));
    });

    test('single block encrypt matches NIST ECB value', () {
      // NIST SP 800-38A: ECB encryption of the first plaintext block.
      final aes = Aes.withKey(hx(aes128Vectors['key'] as String));
      final block = hx(aes128Vectors['pt'] as String).sublist(0, 16);
      aes.encryptBlock(block);
      expect(hex(block), '3ad77bb40d7a3660a89ecaf32466ef97');
    });

    test('decrypt single block matches NIST ECB value', () {
      final aes = Aes.withKey(hx(aes128Vectors['key'] as String));
      final block = hx('3ad77bb40d7a3660a89ecaf32466ef97');
      aes.decryptBlock(block);
      expect(hex(block), hex(hx(aes128Vectors['pt'] as String).sublist(0, 16)));
    });

    test('stateful iv persists across chunked decrypt', () {
      final aes = Aes.withKey(hx(aes128Vectors['key'] as String));
      final ct = hx(aes128Vectors['ct'] as String);
      final pt = List<int>.of(hx(aes128Vectors['pt'] as String));
      final d = AesCbcDecryptor(aes, hx(aes128Vectors['iv'] as String));
      final out = <int>[
        ...d.decrypt(ct.sublist(0, 16)),
        ...d.decrypt(ct.sublist(16)),
      ];
      expect(hex(out), hex(pt));
    });
  });
}

List<int> _text(String s) => s.codeUnits.map((u) => u & 0xff).toList();

List<int> _utf16le(String s) {
  final out = <int>[];
  for (final u in s.codeUnits) {
    out.add(u & 0xff);
    out.add((u >> 8) & 0xff);
  }
  return out;
}
