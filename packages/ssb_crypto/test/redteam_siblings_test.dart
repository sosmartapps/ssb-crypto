// Sibling sweep, red team 2026-10-26. One test per confirmed finding of the
// five past classes (001 secret read after an await, 002 freshness/replay,
// 003 unbound identifiers, argon2id parameters, 004 ambiguous encoding).
// Tests marked KNOWN GAP pin behaviour that is NOT fixed (design decision or
// latent), so a future fix has to update them on purpose.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

void main() {
  group('004-class: integers are range-checked before they are encoded', () {
    test('u16be / u32be refuse values that would wrap', () {
      expect(u16be(0), [0, 0]);
      expect(u16be(0xffff), [255, 255]);
      expect(u32be(0xffffffff), [255, 255, 255, 255]);
      for (final v in [-1, 0x10000, 0x7fffffff, 1 << 40]) {
        expect(() => u16be(v), throwsSsb, reason: 'u16be($v)');
      }
      for (final v in [-1, 0x100000000, 1 << 40]) {
        expect(() => u32be(v), throwsSsb, reason: 'u32be($v)');
      }
    });

    test('POC: an item sealed under epoch 0 used to open under epoch 2^32 (and -1 under 2^32-1)', () async {
      final tk = randomBytes(32);
      final s = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 0, itemId: 'i', plaintext: bytes('p'));
      await expectLater(ItemCrypto.open(vaultId: 'v', tierKey: tk, tierEpoch: 0x100000000, item: s), throwsSsb);
      expect(() => ItemCrypto.keyContext('v', Tier.ice, 0x100000000, 'i'), throwsSsb);
      expect(() => VaultKeyring.tkContext('v', Tier.ice, -1), throwsSsb);
      expect(() => VaultKeyring.vkContext('v', 'unlock', 1 << 32), throwsSsb);
      expect(() => TierExportCrypto.context('v', Tier.ice, 1, -5, Uint8List(32)), throwsSsb);
    });

    test('lengths: a 65536-byte request id / vault id cannot wrap a u16 length prefix', () async {
      final longId = 'r' * 65536;
      final kp = await XWing.generateKeyPair();
      await expectLater(
          DenyReason.seal(recipientPublicKey: kp.publicKey, requestId: longId, reason: 'no'), throwsSsb);
      await expectLater(OwnerToken.compute(vaultId: longId, vaultKey: randomBytes(32)), throwsSsb);
      await expectLater(SafetyNumber.fingerprint(beneficiaryId: longId, publicKey: kp.publicKey), throwsSsb);
      // just under the limit still works
      final ok = await OwnerToken.compute(vaultId: 'r' * 65535, vaultKey: randomBytes(32));
      expect(ok.length, 128);
    });
  });

  group('001-class: caller buffers are read once, before the first await', () {
    Future<void> sealAndCheck(XWingKeyPair kp, int hops) async {
      final pk = Uint8List.fromList(kp.publicKey);
      final pending = XWing.encapsulate(pk);
      for (var i = 0; i < hops; i++) {
        await Future<void>.value();
      }
      wipe(pk); // a lock / dispose / cache eviction landing mid-flight
      final e = await pending;
      final back = await XWing.decapsulate(e.ciphertext, kp.secretKey);
      expect(back, e.sharedSecret, reason: 'hops=$hops: sealed to a key that is not the recipient\'s');
    }

    test('XWing.encapsulate: wiping the recipient key after the call never changes the recipient', () async {
      final kp = await XWing.generateKeyPair();
      for (var hops = 0; hops < 40; hops++) {
        await sealAndCheck(kp, hops);
      }
    });

    test('Hpke.seal: wiping the recipient key after the call still seals to the original recipient', () async {
      final kp = await XWing.generateKeyPair();
      for (var hops = 0; hops < 25; hops++) {
        final pk = Uint8List.fromList(kp.publicKey);
        final pending = Hpke.seal(pk, bytes('hello'), info: bytes('i'));
        for (var i = 0; i < hops; i++) {
          await Future<void>.value();
        }
        wipe(pk);
        final sealed = await pending;
        expect(await Hpke.open(kp.secretKey, sealed, info: bytes('i')), bytes('hello'), reason: 'hops=$hops');
      }
    });

    test('Release.create: the beneficiary key is snapshotted before Shamir.split yields', () async {
      final kp = await XWing.generateKeyPair();
      final pk = Uint8List.fromList(kp.publicKey);
      final pending = Release.create(
          vaultId: 'v', beneficiaryId: 'b', tier: Tier.secrets, tierKey: randomBytes(32),
          beneficiaryPublicKey: pk, epoch: 1);
      wipe(pk);
      final bundle = await pending;
      final key = await Release.recoverWithServerShare(
          vaultId: 'v', beneficiaryId: 'b', tier: Tier.secrets,
          beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare,
          beneficiarySecretKey: kp.secretKey);
      expect(key.key.length, 32);
    });
  });

  group('002-class: overlapping tier exports chain instead of forking', () {
    test('POC: two un-awaited sealTierExport calls used to share seq and prevHash', () async {
      final ring = VaultKeyring.create('v-exp');
      final tk = Uint8List.fromList(ring.tierKey(Tier.secrets));
      final f1 = ring.sealTierExport(Tier.secrets, bytes('one'));
      final f2 = ring.sealTierExport(Tier.secrets, bytes('two'));
      final e1 = await f1, e2 = await f2;
      expect(e1.header.seq, 1);
      expect(e2.header.seq, 2, reason: 'forked chain: both exports claim seq ${e1.header.seq}');
      expect(e2.header.prevHash, TierExportCrypto.hash(e1.ciphertext));
      expect(ring.tierExportSeq(Tier.secrets), 2);
      expect(ring.tierExportHead(Tier.secrets), hexEncode(TierExportCrypto.hash(e2.ciphertext)));
      expect(
          await TierExportCrypto.open(
              vaultId: 'v-exp', tier: Tier.secrets, tierKey: tk, header: e2.header, ciphertext: e2.ciphertext),
          bytes('two'));
    });

    test('a queued export keeps the key, epoch and plaintext it was called with (rotate / mutate after the call)', () async {
      final ring = VaultKeyring.create('v-exp2');
      final tkOld = Uint8List.fromList(ring.tierKey(Tier.essentials));
      final pt = bytes('first');
      final f1 = ring.sealTierExport(Tier.essentials, bytes('zero'));
      final f2 = ring.sealTierExport(Tier.essentials, pt);
      ring.rotateTier(Tier.essentials); // wipes the old key in place
      wipe(pt);
      await f1;
      final e2 = await f2;
      expect(e2.header.epoch, 1, reason: 'sealed under the generation it was called with');
      expect(
          await TierExportCrypto.open(
              vaultId: 'v-exp2', tier: Tier.essentials, tierKey: tkOld, header: e2.header, ciphertext: e2.ciphertext),
          bytes('first'));
    });

    test('a disposed ring refuses to export and does not advance the chain', () async {
      final ring = VaultKeyring.create('v-exp3');
      ring.dispose();
      await expectLater(ring.sealTierExport(Tier.ice, bytes('x')), throwsSsb);
      expect(ring.tierExportSeq(Tier.ice), 0);
    });
  });

  group('002-class: freshness gaps that remain (KNOWN GAP, pinned)', () {
    test('KNOWN GAP (latent, the app stores no files): an older version of a FILE with the same id still opens at the same epoch', () async {
      // Items are bound to the manifest through itemsHash; files are not. A
      // server that kept the first version of file "f" can serve it back after
      // an edit and nothing detects it (a tier rotation does: the epoch is in
      // the wrap AAD). Fix when files ship: put (fileId, tier, wrappedKey) in a
      // manifest `filesHash`.
      final tk = randomBytes(32);
      final (wk1, st1) = await ItemCrypto.sealFile(
          vaultId: 'v', tier: Tier.secrets, tierKey: tk, tierEpoch: 1, fileId: 'f', data: bytes('version 1'));
      final (wk2, st2) = await ItemCrypto.sealFile(
          vaultId: 'v', tier: Tier.secrets, tierKey: tk, tierEpoch: 1, fileId: 'f', data: bytes('version 2'));
      expect(
          await ItemCrypto.openFile(
              vaultId: 'v', tier: Tier.secrets, tierKey: tk, tierEpoch: 1, fileId: 'f',
              wrappedKey: wk1, stream: st1),
          bytes('version 1'),
          reason: 'when this starts failing the gap was closed: delete this test');
      expect(wk2.length, wk1.length);
      expect(st2.isNotEmpty, isTrue);
    });
  });

  group('argon2id parameters', () {
    test('Unlock refuses every sub-minimum parameter set from JSON, each dimension separately', () async {
      final sk = randomBytes(16), salt = randomBytes(16);
      for (final j in <Map<String, int>>[
        {'m': 65535, 't': 3, 'p': 1},
        {'m': 65536, 't': 2, 'p': 1},
        {'m': 8, 't': 3, 'p': 1},
        {'m': 1, 't': 1, 'p': 1},
      ]) {
        await expectLater(
            (() async => Unlock.deriveUnlockKey(
                passphrase: 'pw', secretKey: sk, accountSalt: salt, params: Argon2Params.fromJson(j)))(),
            throwsSsb,
            reason: '$j');
      }
    });

    test('fromJson(allowTestOnly) only ever yields the exact testOnly constant, nothing in between', () {
      expect(Argon2Params.fromJson({'m': 1024, 't': 1, 'p': 1}, allowTestOnly: true), same(Argon2Params.testOnly));
      final nearly = Argon2Params.fromJson({'m': 1024, 't': 2, 'p': 1}, allowTestOnly: true);
      expect(() => nearly.validateForUnlock(), throwsSsb);
      final off = Argon2Params.fromJson({'m': 1024, 't': 1, 'p': 1});
      expect(() => off.validateForUnlock(), throwsSsb, reason: 'without the flag it is a plain sub-minimum set');
    });

    test('KNOWN GAP (by design): the raw argon2id() export only runs validate(), not the unlock floor', () async {
      // Only Unlock.deriveUnlockKey gates on the floor, and it is the only
      // in-tree caller. A new caller of argon2id() must call
      // validateForUnlock() itself.
      final k = await argon2id(bytes('pw'), randomBytes(16),
          const Argon2Params.testing(memoryKiB: 64, iterations: 1, parallelism: 1));
      expect(k.length, 32);
    });
  });
}
