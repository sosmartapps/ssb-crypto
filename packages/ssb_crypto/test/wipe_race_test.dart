// Regression tests for report SSB-2026-001 (external, 2026-10-15):
// a secret buffer that is wiped or rotated while an async seal is still
// pending must not change what gets sealed. Dart runs an async body
// synchronously up to its first await, so `wrapTierKey(t)` followed by
// `rotateTier(t)` without an await in between used to wipe the plaintext
// before AES-GCM read it, and the stored wrapped tier key became 32 zero
// bytes with no error anywhere.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

bool _allZero(Uint8List b) => b.every((x) => x == 0);

Uint8List _copy(Uint8List b) => Uint8List.fromList(b);

void main() {
  group('in-flight wrap survives a concurrent wipe', () {
    test('rotateTier() during wrapTierKey() seals the OLD key, not zeros', () async {
      for (var trial = 0; trial < 20; trial++) {
        final kr = VaultKeyring.create('vault-A');
        final oldTk = _copy(kr.tierKeys[Tier.ice]!);
        final pending = kr.wrapTierKey(Tier.ice); // not awaited yet
        kr.rotateTier(Tier.ice); // wipes the buffer wrapTierKey was given
        final wrapped = await pending;
        final pt = await Aead.open(kr.vaultKey, wrapped,
            type: ObjectType.wrappedKey,
            context: utf8Bytes('ssb/v1/tk/ice|vault:vault-A'));
        expect(_allZero(pt), isFalse, reason: 'trial $trial sealed a zero key');
        expect(pt, equals(oldTk));
      }
    });

    test('dispose() during wrapTierKey() seals the real key under the real vault key', () async {
      final kr = VaultKeyring.create('vault-B');
      final vk = _copy(kr.vaultKey);
      final tk = _copy(kr.tierKeys[Tier.secrets]!);
      final pending = kr.wrapTierKey(Tier.secrets);
      kr.dispose();
      final wrapped = await pending;
      // Must open under the ORIGINAL vault key (so the key was not read after
      // the wipe either) and yield the original tier key.
      final pt = await Aead.open(vk, wrapped,
          type: ObjectType.wrappedKey,
          context: utf8Bytes('ssb/v1/tk/secrets|vault:vault-B'));
      expect(pt, equals(tk));
    });

    test('dispose() during wrapVaultKey() seals the real vault key', () async {
      final kr = VaultKeyring.create('vault-C');
      final vk = _copy(kr.vaultKey);
      final kek = randomBytes(32);
      final pending = kr.wrapVaultKey(kek, slot: 'unlock');
      kr.dispose();
      final wrapped = await pending;
      final pt = await Aead.open(kek, wrapped,
          type: ObjectType.wrappedKey,
          context: utf8Bytes('ssb/v1/vk/unlock|vault:vault-C'));
      expect(pt, equals(vk));
    });

    test('Aead.seal snapshots key, plaintext and context before its first await', () async {
      final key = randomBytes(32);
      final keyCopy = _copy(key);
      final pt = Uint8List.fromList(List.generate(40, (i) => i + 1));
      final ptCopy = _copy(pt);
      final ctx = utf8Bytes('ctx');
      final pending = Aead.seal(key, pt, type: ObjectType.item, context: ctx);
      wipe(key);
      wipe(pt);
      ctx.fillRange(0, ctx.length, 0x41);
      final sealed = await pending;
      final opened = await Aead.open(keyCopy, sealed,
          type: ObjectType.item, context: utf8Bytes('ctx'));
      expect(opened, equals(ptCopy));
    });

    test('StreamCipher.encrypt snapshots the file key before its first await', () async {
      final fk = randomBytes(32);
      final fkCopy = _copy(fk);
      final data = randomBytes(200 * 1024); // several chunks
      final pending = StreamCipher.encrypt(fk, data, context: utf8Bytes('f'));
      wipe(fk);
      final blob = await pending;
      final out = await StreamCipher.decrypt(fkCopy, blob, context: utf8Bytes('f'));
      expect(out, equals(data));
    });

    test('end to end: a raced rotation can no longer plant a zero tier key', () async {
      final kr = VaultKeyring.create('vault-X');
      final vk = _copy(kr.vaultKey);
      final stored = {for (final t in Tier.values) t: await kr.wrapTierKey(t)};
      final pending = kr.wrapTierKey(Tier.ice);
      kr.rotateTier(Tier.ice);
      stored[Tier.ice] = await pending;
      final reopened = await VaultKeyring.fromVaultKey(
          vaultId: 'vault-X', vaultKey: vk, wrappedTierKeys: stored);
      expect(_allZero(reopened.tierKeys[Tier.ice]!), isFalse);
    });
  });

  group('every other secret-taking entry point snapshots before its first await', () {
    test('ItemCrypto.rewrapItemKey snapshots newTierKey (audit F1)', () async {
      final tk1 = randomBytes(32), tk2 = randomBytes(32);
      final tk2Copy = _copy(tk2);
      final item = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk1, itemId: 'i', plaintext: utf8Bytes('x'));
      final pending = ItemCrypto.rewrapItemKey(
          vaultId: 'v', item: item, oldTierKey: tk1, newTier: Tier.ice, newTierKey: tk2);
      wipe(tk2); // lands during the unwrap await
      final re = await pending;
      expect(await ItemCrypto.open(vaultId: 'v', tierKey: tk2Copy, item: re), equals(utf8Bytes('x')));
    });

    test('ItemCrypto.seal / sealFile snapshot the plaintext (audit F4)', () async {
      final tk = randomBytes(32);
      final pt = utf8Bytes('hello world');
      final pending = ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, itemId: 'i', plaintext: pt);
      wipe(pt);
      final item = await pending;
      expect(await ItemCrypto.open(vaultId: 'v', tierKey: tk, item: item), equals(utf8Bytes('hello world')));

      final data = randomBytes(5000);
      final dataCopy = _copy(data);
      final pendingFile = ItemCrypto.sealFile(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, fileId: 'f', data: data);
      wipe(data);
      final (wk, stream) = await pendingFile;
      expect(
          await ItemCrypto.openFile(
              vaultId: 'v', tier: Tier.ice, tierKey: tk, fileId: 'f', wrappedKey: wk, stream: stream),
          equals(dataCopy));
    });

    test('Shamir.split and Release.create snapshot the secret (audit F2)', () async {
      final secret = randomBytes(32);
      final secretCopy = _copy(secret);
      final pending = Shamir.split(secret);
      wipe(secret);
      final shares = await pending;
      expect(await Shamir.combine([shares[0], shares[2]]), equals(secretCopy));

      final tk = randomBytes(32);
      final tkCopy = _copy(tk);
      final kp = await XWing.generateKeyPair();
      final pendingRelease = Release.create(
          vaultId: 'v', beneficiaryId: 'b', tier: Tier.secrets,
          tierKey: tk, beneficiaryPublicKey: kp.publicKey);
      wipe(tk);
      final bundle = await pendingRelease;
      expect(
          await Release.recoverOffline(
              beneficiaryKitCode: bundle.beneficiaryKitCode, attorneyKitCode: bundle.attorneyKitCode),
          equals(tkCopy));
    });

    test('hkdfSha384 snapshots ikm', () async {
      final ikm = randomBytes(32);
      final salt = randomBytes(16);
      final expected = await hkdfSha384(ikm: _copy(ikm), salt: salt, info: 't');
      final pending = hkdfSha384(ikm: ikm, salt: salt, info: 't');
      wipe(ikm);
      expect(await pending, equals(expected));
    });

    test('Unlock.deriveUnlockKey snapshots the Secret Key before Argon2 (audit F3)', () async {
      final sk = Unlock.newSecretKey();
      final salt = Unlock.newAccountSalt();
      final expected = await Unlock.deriveUnlockKey(
          passphrase: 'pw', secretKey: _copy(sk), accountSalt: salt, params: Argon2Params.testOnly);
      final pending = Unlock.deriveUnlockKey(
          passphrase: 'pw', secretKey: sk, accountSalt: salt, params: Argon2Params.testOnly);
      wipe(sk);
      expect(await pending, equals(expected));
    });

    test('Hpke.seal snapshots plaintext and info (audit F5)', () async {
      final kp = await XWing.generateKeyPair();
      final pt = utf8Bytes('share bytes');
      final info = utf8Bytes('info');
      final pending = Hpke.seal(kp.publicKey, pt, info: info);
      wipe(pt);
      wipe(info);
      final sealed = await pending;
      expect(await Hpke.open(kp.secretKey, sealed, info: utf8Bytes('info')), equals(utf8Bytes('share bytes')));
    });

    test('KitCode.encode snapshots the payload (audit F5)', () async {
      final payload = randomBytes(32);
      final copy = _copy(payload);
      final pending = KitCode.encode('SSB1-RK', payload);
      wipe(payload);
      final code = await pending;
      expect(await KitCode.decode('SSB1-RK', code, payloadLength: 32), equals(copy));
    });

    test('XWing.generateKeyPairDerand snapshots the seed (audit F5)', () async {
      final seed = randomBytes(XWing.secretKeyLength);
      final pending = XWing.generateKeyPairDerand(seed);
      wipe(seed);
      final kp = await pending;
      final e = await XWing.encapsulate(kp.publicKey);
      expect(await XWing.decapsulate(e.ciphertext, kp.secretKey), equals(e.sharedSecret));
    });
  });

  group('wiped material can no longer be used silently', () {
    test('a disposed keyring refuses to wrap, rotate or hand out keys', () async {
      final kr = VaultKeyring.create('v');
      kr.dispose();
      expect(kr.isDisposed, isTrue);
      expect(() => kr.tierKey(Tier.ice), throwsA(isA<SsbCryptoException>()));
      expect(() => kr.rotateTier(Tier.ice), throwsA(isA<SsbCryptoException>()));
      expect(() => kr.wrapTierKey(Tier.ice), throwsA(isA<SsbCryptoException>()));
      expect(() => kr.wrapVaultKey(randomBytes(32), slot: 's'), throwsA(isA<SsbCryptoException>()));
    });

    test('an all-zero key is rejected by Aead and StreamCipher (tripwire)', () async {
      final zero = Uint8List(32);
      await expectLater(
          Aead.seal(zero, utf8Bytes('x'), type: ObjectType.item), throwsA(isA<SsbCryptoException>()));
      await expectLater(
          Aead.open(zero, Uint8List(64), type: ObjectType.item), throwsA(isA<SsbCryptoException>()));
      await expectLater(StreamCipher.encrypt(zero, utf8Bytes('x')), throwsA(isA<SsbCryptoException>()));
      // ...so re-wrapping under a wiped tier key fails instead of succeeding.
      final tk1 = randomBytes(32);
      final item = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk1, itemId: 'i', plaintext: utf8Bytes('x'));
      await expectLater(
          ItemCrypto.rewrapItemKey(
              vaultId: 'v', item: item, oldTierKey: tk1, newTier: Tier.ice, newTierKey: zero),
          throwsA(isA<SsbCryptoException>()));
    });

    test('StreamCipher.encrypt refuses a chunk size its own decrypt would reject', () async {
      await expectLater(
          StreamCipher.encrypt(randomBytes(32), utf8Bytes('x'), chunkSize: StreamCipher.maxChunkSize + 1),
          throwsA(isA<SsbCryptoException>()));
    });
  });

  group('no aliasing of caller buffers', () {
    test('rewrapItemKey returns a body that is not the input buffer', () async {
      final tk1 = randomBytes(32), tk2 = randomBytes(32);
      final item = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk1, itemId: 'i',
          plaintext: utf8Bytes('hello'));
      final re = await ItemCrypto.rewrapItemKey(
          vaultId: 'v', item: item, oldTierKey: tk1, newTier: Tier.ice, newTierKey: tk2);
      expect(identical(re.body, item.body), isFalse);
      wipe(item.body); // "wiping the old item" must not destroy the new one
      final pt = await ItemCrypto.open(vaultId: 'v', tierKey: tk2, item: re);
      expect(pt, equals(utf8Bytes('hello')));
    });

    test('fromVaultKey copies the vault key, so dispose() cannot zero the caller buffer', () async {
      final kr = VaultKeyring.create('v');
      final wrapped = {for (final t in Tier.values) t: await kr.wrapTierKey(t)};
      final callerVk = _copy(kr.vaultKey);
      final kr2 = await VaultKeyring.fromVaultKey(
          vaultId: 'v', vaultKey: callerVk, wrappedTierKeys: wrapped);
      expect(identical(kr2.vaultKey, callerVk), isFalse);
      kr2.dispose();
      expect(callerVk, equals(kr.vaultKey));
    });
  });

  group('failure paths still fail closed', () {
    test('VaultKeyring.open with one corrupt tier wrap throws (and leaks nothing it can reach)', () async {
      final kr = VaultKeyring.create('v');
      final kek = randomBytes(32);
      final wvk = await kr.wrapVaultKey(kek, slot: 'unlock');
      final wrapped = {for (final t in Tier.values) t: await kr.wrapTierKey(t)};
      final bad = _copy(wrapped[Tier.secrets]!);
      bad[bad.length - 1] ^= 1;
      wrapped[Tier.secrets] = bad;
      expect(
        () => VaultKeyring.open(
            vaultId: 'v', kek: kek, slot: 'unlock',
            wrappedVaultKey: wvk, wrappedTierKeys: wrapped),
        throwsA(isA<SsbCryptoException>()),
      );
    });

    test('Release.recoverOffline rejects a tampered kit and still recovers a good one', () async {
      final tk = randomBytes(32);
      final kp = await XWing.generateKeyPair();
      final b = await Release.create(
          vaultId: 'v', beneficiaryId: 'b', tier: Tier.essentials,
          tierKey: tk, beneficiaryPublicKey: kp.publicKey);
      final got = await Release.recoverOffline(
          beneficiaryKitCode: b.beneficiaryKitCode, attorneyKitCode: b.attorneyKitCode);
      expect(got, equals(tk));
      expect(
        () => Release.recoverOffline(
            beneficiaryKitCode: b.beneficiaryKitCode, attorneyKitCode: b.beneficiaryKitCode),
        throwsA(isA<SsbCryptoException>()),
      );
    });
  });
}
