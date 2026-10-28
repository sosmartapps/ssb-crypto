import 'dart:convert';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Matcher get throwsSsb => throwsA(isA<SsbCryptoException>());
Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  group('Vault key hierarchy', () {
    test('unlock and recovery slots both open the vault', () async {
      final anchor = InMemoryAnchor();
      final ring = VaultKeyring.create('v1', anchor: anchor);
      final muk = randomBytes(32), rk = randomBytes(32);
      final wUnlock = await ring.wrapVaultKey(muk, slot: 'unlock', epoch: 1);
      final wRecovery = await ring.wrapVaultKey(rk, slot: 'recovery', epoch: 1);
      final wTiers = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
      final manifest = await ring.sealManifest(items: const []);
      await ring.commitManifest();
      final slotEpochs = Map.of(ring.slotEpochs);
      Future<VaultKeyring> open({String vaultId = 'v1', required Uint8List kek, required String slot, required Uint8List wvk}) =>
          VaultKeyring.open(vaultId: vaultId, kek: kek, slot: slot, wrappedVaultKey: wvk, slotEpochs: slotEpochs,
              manifestBlob: manifest, wrappedTierKeys: wTiers, items: const [], anchor: anchor);
      final a = await open(kek: muk, slot: 'unlock', wvk: wUnlock);
      final c = await open(kek: rk, slot: 'recovery', wvk: wRecovery);
      expect(a.tierKeys[Tier.secrets], ring.tierKeys[Tier.secrets]);
      expect(c.vaultKey, ring.vaultKey);
      expect(a.tierEpochs, ring.tierEpochs);
      expect(a.slotEpochs, {'unlock': 1, 'recovery': 1});
      // Slot and vault id are bound in.
      await expectLater(open(kek: muk, slot: 'recovery', wvk: wUnlock), throwsSsb);
      await expectLater(open(vaultId: 'v2', kek: muk, slot: 'unlock', wvk: wUnlock), throwsSsb);
      final code = await VaultKeyring.formatRecoveryKey(rk);
      expect(await VaultKeyring.parseRecoveryKey(code), rk);
    });

    test('items: round trip, tier isolation, no cut-and-paste, sizes hidden', () async {
      final ring = VaultKeyring.create('v1');
      Future<SealedItem> seal(String id, String text) => ItemCrypto.seal(vaultId: 'v1', tier: Tier.secrets,
          tierKey: ring.tierKey(Tier.secrets), tierEpoch: ring.tierEpoch(Tier.secrets), itemId: id, plaintext: b(text));
      Future<Uint8List> open(Tier keyTier, SealedItem item, {int? epoch}) => ItemCrypto.open(
          vaultId: 'v1', tierKey: ring.tierKey(keyTier), tierEpoch: epoch ?? ring.tierEpoch(keyTier), item: item);
      final item = await seal('i1', 'iPhone passcode 123456');
      expect(await open(Tier.secrets, item), b('iPhone passcode 123456'));
      // The essentials tier key must not open a secrets item.
      await expectLater(open(Tier.essentials, item), throwsSsb);
      // Claiming it is an essentials item fails too (tier is bound in).
      await expectLater(open(Tier.secrets, SealedItem('i1', Tier.essentials, item.wrappedItemKey, item.body)), throwsSsb);
      // Moving a body under another item id fails.
      await expectLater(open(Tier.secrets, SealedItem('i2', Tier.secrets, item.wrappedItemKey, item.body)), throwsSsb);
      // Claiming another epoch fails (epoch is bound in).
      await expectLater(open(Tier.secrets, item, epoch: 2), throwsSsb);
      // Short items all pad to the same size.
      final tiny = await seal('i3', 'x');
      expect(tiny.body.length, item.body.length);
    });

    test('tier rotation re-wraps without re-encrypting bodies, and bumps the epoch', () async {
      final ring = VaultKeyring.create('v1');
      final old = Uint8List.fromList(ring.tierKeys[Tier.secrets]!);
      final item = await ItemCrypto.seal(vaultId: 'v1', tier: Tier.secrets,
          tierKey: old, tierEpoch: 1, itemId: 'i1', plaintext: b('pw'));
      ring.rotateTier(Tier.secrets);
      expect(ring.tierEpoch(Tier.secrets), 2);
      expect(ring.tierEpoch(Tier.ice), 1);
      final moved = await ItemCrypto.rewrapItemKey(vaultId: 'v1', item: item,
          oldTierKey: old, oldTierEpoch: 1, newTier: Tier.secrets, newTierKey: ring.tierKeys[Tier.secrets]!, newTierEpoch: 2);
      // Equal bytes, but never the same buffer (SSB-2026-001 follow-up).
      expect(moved.body, equals(item.body));
      expect(identical(moved.body, item.body), isFalse);
      expect(await ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!, tierEpoch: 2, item: moved), b('pw'));
      await expectLater(ItemCrypto.open(vaultId: 'v1', tierKey: old, tierEpoch: 1, item: moved), throwsSsb);
      await expectLater(ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!, tierEpoch: 1, item: moved), throwsSsb);
    });

    test('files round trip through STREAM', () async {
      final ring = VaultKeyring.create('v1');
      final data = randomBytes(200 * 1024);
      final (wk, stream) = await ItemCrypto.sealFile(vaultId: 'v1', tier: Tier.essentials,
          tierKey: ring.tierKeys[Tier.essentials]!, tierEpoch: 1, fileId: 'will.pdf', data: data);
      expect(await ItemCrypto.openFile(vaultId: 'v1', tier: Tier.essentials,
          tierKey: ring.tierKeys[Tier.essentials]!, tierEpoch: 1, fileId: 'will.pdf', wrappedKey: wk, stream: stream), data);
      await expectLater(ItemCrypto.openFile(vaultId: 'v1', tier: Tier.essentials,
          tierKey: ring.tierKeys[Tier.essentials]!, tierEpoch: 2, fileId: 'will.pdf', wrappedKey: wk, stream: stream), throwsSsb);
    });

    test('Padmé bucket sizes grow slowly', () {
      expect(ItemCrypto.padmeLength(256), 256);
      expect(ItemCrypto.padmeLength(1000), greaterThanOrEqualTo(1000));
      expect(ItemCrypto.padmeLength(1000000) - 1000000, lessThan(1000000 * 0.12));
    });
  });

  group('Two-key release', () {
    test('end to end: S1+S2 after release, S1+S3 offline, nothing alone', () async {
      final ring = VaultKeyring.create('v1');
      final tk = ring.tierKeys[Tier.secrets]!;
      final beneficiary = await XWing.generateKeyPair();
      final bundle = await Release.create(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.secrets, tierKey: tk, beneficiaryPublicKey: beneficiary.publicKey, epoch: 1);
      expect(bundle.beneficiaryKitCode, startsWith('SSB2-BK-'));
      expect(bundle.attorneyKitCode, startsWith('SSB2-AK-'));

      final online = await Release.recoverWithServerShare(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.secrets, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare, beneficiarySecretKey: beneficiary.secretKey);
      expect(online.key, tk);
      expect(online.epoch, 1);
      final offline = await Release.recoverOffline(beneficiaryKitCode: bundle.beneficiaryKitCode,
          attorneyKitCode: bundle.attorneyKitCode);
      expect(offline.key, tk);
      expect(offline.epoch, 1);

      // Server share cannot be opened by anyone else, or replayed for another tier/beneficiary.
      final mallory = await XWing.generateKeyPair();
      await expectLater(Release.recoverWithServerShare(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.secrets, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare, beneficiarySecretKey: mallory.secretKey), throwsSsb);
      await expectLater(Release.recoverWithServerShare(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.essentials, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare, beneficiarySecretKey: beneficiary.secretKey), throwsSsb);
      await expectLater(Release.recoverWithServerShare(vaultId: 'v1', beneficiaryId: 'b2',
          tier: Tier.secrets, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare, beneficiarySecretKey: beneficiary.secretKey), throwsSsb);
      // A kit from a different release is caught before it yields a wrong key.
      final other = await Release.create(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.secrets, tierKey: randomBytes(32), beneficiaryPublicKey: beneficiary.publicKey, epoch: 1);
      await expectLater(Release.recoverOffline(beneficiaryKitCode: other.beneficiaryKitCode,
          attorneyKitCode: bundle.attorneyKitCode), throwsSsb);
      // An attorney kit is not accepted where a beneficiary kit is expected.
      await expectLater(Release.recoverOffline(beneficiaryKitCode: bundle.attorneyKitCode,
          attorneyKitCode: bundle.attorneyKitCode), throwsSsb);
    });
  });

  group('Safety numbers', () {
    test('deterministic, key- and id-sensitive, 60 digits', () async {
      final k1 = await XWing.generateKeyPair(), k2 = await XWing.generateKeyPair();
      final a = await SafetyNumber.fingerprint(beneficiaryId: 'b1', publicKey: k1.publicKey);
      expect(await SafetyNumber.fingerprint(beneficiaryId: 'b1', publicKey: k1.publicKey), a);
      expect(SafetyNumber.matches(a,
          await SafetyNumber.fingerprint(beneficiaryId: 'b1', publicKey: k2.publicKey)), isFalse);
      expect(SafetyNumber.matches(a,
          await SafetyNumber.fingerprint(beneficiaryId: 'b2', publicKey: k1.publicKey)), isFalse);
      final d = SafetyNumber.digits(a);
      expect(RegExp(r'^(\d{5} ){11}\d{5}$').hasMatch(d), isTrue);
    });
  });
}
