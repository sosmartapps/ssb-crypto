import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Matcher get throwsSsb => throwsA(isA<SsbCryptoException>());

void main() {
  group('KDFs', () {
    test('HKDF-SHA384 matches an independent (Python hmac) computation', () async {
      final out = await hkdfSha384(
          ikm: List.generate(32, (i) => i),
          salt: List.generate(16, (i) => 100 + i),
          info: 'ssb/v1/test');
      expect(hexEncode(out), '82f33b79d5db83567f78b23444dc8273d59cd57558d97e31287ebe5401722500');
    });

    test('Argon2id library matches RFC 9106 §5.3 test vector', () async {
      final k = await Argon2id(memory: 32, iterations: 3, parallelism: 4, hashLength: 32).deriveKey(
        secretKey: SecretKeyData(List.filled(32, 1)),
        nonce: List.filled(16, 2),
        optionalSecret: List.filled(8, 3),
        associatedData: List.filled(12, 4),
      );
      expect(hexEncode(await k.extractBytes()),
          '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    });

    test('unlock key needs both passphrase and Secret Key', () async {
      final sk = Unlock.newSecretKey(), salt = Unlock.newAccountSalt();
      Future<Uint8List> d(String pw, Uint8List k) => Unlock.deriveUnlockKey(
          passphrase: pw, secretKey: k, accountSalt: salt, params: Argon2Params.testOnly);
      final a = await d('correct horse', sk);
      expect(await d('correct horse', sk), a);
      expect(await d('correct horsf', sk), isNot(a));
      expect(await d('correct horse', Unlock.newSecretKey()), isNot(a));
    });

    test('production Argon2 params meet the spec floor', () {
      expect(Argon2Params.production.memoryKiB, greaterThanOrEqualTo(128 * 1024));
      expect(Argon2Params.minimum.memoryKiB, greaterThanOrEqualTo(64 * 1024));
    });
  });

  group('Kit codes', () {
    test('round trip, forgiving input, label binding, typo detection', () async {
      final sk = Unlock.newSecretKey();
      final code = await Unlock.formatSecretKey(sk);
      expect(code, startsWith('SSB1-SK-'));
      expect(await Unlock.parseSecretKey(code), sk);
      expect(await Unlock.parseSecretKey(code.toLowerCase().replaceAll('-', ' ')), sk);
      // Wrong label (a recovery-key parser must reject a secret key).
      await expectLater(KitCode.decode('SSB1-RK', code, payloadLength: 16), throwsSsb);
      // Single-character typo.
      final chars = code.split('');
      final i = code.length - 3;
      chars[i] = chars[i] == '7' ? '8' : '7';
      await expectLater(Unlock.parseSecretKey(chars.join()), throwsSsb);
    });
  });

  group('AEAD with versioned header', () {
    final key = randomBytes(32);
    test('round trip and header layout', () async {
      final blob = await Aead.seal(key, Uint8List.fromList([1, 2, 3]),
          type: ObjectType.item, context: [9]);
      expect(blob.sublist(0, 6), [0x53, 0x53, 0x42, 1, Suite.v1, ObjectType.item.code]);
      expect(await Aead.open(key, blob, type: ObjectType.item, context: [9]), [1, 2, 3]);
    });
    test('rejects tamper, wrong context, wrong type, downgrade, wrong key', () async {
      final blob = await Aead.seal(key, Uint8List(10), type: ObjectType.item, context: [9]);
      Uint8List flip(int i) => Uint8List.fromList(blob)..[i] ^= 1;
      await expectLater(Aead.open(key, flip(blob.length - 1), type: ObjectType.item, context: [9]), throwsSsb);
      await expectLater(Aead.open(key, flip(10), type: ObjectType.item, context: [9]), throwsSsb);
      await expectLater(Aead.open(key, blob, type: ObjectType.item, context: [8]), throwsSsb);
      await expectLater(Aead.open(key, blob, type: ObjectType.wrappedKey, context: [9]), throwsSsb);
      await expectLater(Aead.open(key, flip(4), type: ObjectType.item, context: [9]), throwsSsb); // suite byte
      await expectLater(Aead.open(randomBytes(32), blob, type: ObjectType.item, context: [9]), throwsSsb);
    });
  });

  group('Shamir 2-of-3', () {
    test('any two shares recover; one does not; mismatches are caught', () async {
      final secret = randomBytes(32);
      final s = await Shamir.split(secret);
      for (final pair in [[0, 1], [0, 2], [1, 2], [2, 0]]) {
        expect(await Shamir.combine([s[pair[0]], s[pair[1]]]), secret);
      }
      await expectLater(Shamir.combine([s[0]]), throwsSsb);
      await expectLater(Shamir.combine([s[0], s[0]]), throwsSsb);
      final other = await Shamir.split(randomBytes(32));
      await expectLater(Shamir.combine([s[0], other[1]]), throwsSsb);
      final bad = Share.fromBytes(s[1].toBytes()..[20] ^= 0x40);
      await expectLater(Shamir.combine([s[0], bad]), throwsSsb);
    });
    test('3-of-5 works and 2 shares are not enough', () async {
      final secret = randomBytes(32);
      final s = await Shamir.split(secret, shares: 5, threshold: 3);
      expect(await Shamir.combine([s[4], s[1], s[3]]), secret);
      await expectLater(Shamir.combine([s[0], s[1]]), throwsSsb);
    });
    test('single share is statistically independent of the secret', () async {
      // Same secret, many splits: share-1 bytes should look uniform.
      final secret = Uint8List(16);
      final counts = List.filled(256, 0);
      for (var i = 0; i < 4096; i++) {
        counts[(await Shamir.split(secret)).first.y[0]]++;
      }
      expect(counts.where((c) => c == 0).length, lessThan(3));
    });
  });

  group('STREAM file encryption', () {
    final key = randomBytes(32);
    for (final n in [0, 1, 15, 16, 17, 64, 65, 200]) {
      test('round trip $n bytes (chunk 16)', () async {
        final data = randomBytes(n);
        final blob = await StreamCipher.encrypt(key, data, chunkSize: 16, context: [1]);
        expect(await StreamCipher.decrypt(key, blob, context: [1]), data);
      });
    }
    test('detects truncation, extension, reordering, wrong context', () async {
      final blob = await StreamCipher.encrypt(key, randomBytes(64), chunkSize: 16);
      const head = 17, chunk = 32;
      await expectLater(StreamCipher.decrypt(key, blob.sublist(0, head + 2 * chunk)), throwsSsb);
      await expectLater(
          StreamCipher.decrypt(key, Uint8List.fromList([...blob, ...blob.sublist(head, head + chunk)])), throwsSsb);
      final swapped = Uint8List.fromList(blob)
        ..setAll(head, blob.sublist(head + chunk, head + 2 * chunk))
        ..setAll(head + chunk, blob.sublist(head, head + chunk));
      await expectLater(StreamCipher.decrypt(key, swapped), throwsSsb);
      await expectLater(StreamCipher.decrypt(key, blob, context: [2]), throwsSsb);
    });
  });
}
