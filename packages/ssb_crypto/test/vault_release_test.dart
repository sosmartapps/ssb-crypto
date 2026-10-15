import 'dart:convert';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Matcher get throwsSsb => throwsA(isA<SsbCryptoException>());
Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  group('Vault key hierarchy', () {
    test('unlock and recovery slots both open the vault', () async {
      final ring = VaultKeyring.create('v1');
      final muk = randomBytes(32), rk = randomBytes(32);
      final wUnlock = await ring.wrapVaultKey(muk, slot: 'unlock');
      final wRecovery = await ring.wrapVaultKey(rk, slot: 'recovery');
      final wTiers = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
      final a = await VaultKeyring.open(vaultId: 'v1', kek: muk, slot: 'unlock',
          wrappedVaultKey: wUnlock, wrappedTierKeys: wTiers);
      final c = await VaultKeyring.open(vaultId: 'v1', kek: rk, slot: 'recovery',
          wrappedVaultKey: wRecovery, wrappedTierKeys: wTiers);
      expect(a.tierKeys[Tier.secrets], ring.tierKeys[Tier.secrets]);
      expect(c.vaultKey, ring.vaultKey);
      // Slot and vault id are bound in.
      await expectLater(VaultKeyring.open(vaultId: 'v1', kek: muk, slot: 'recovery',
          wrappedVaultKey: wUnlock, wrappedTierKeys: wTiers), throwsSsb);
      await expectLater(VaultKeyring.open(vaultId: 'v2', kek: muk, slot: 'unlock',
          wrappedVaultKey: wUnlock, wrappedTierKeys: wTiers), throwsSsb);
      final code = await VaultKeyring.formatRecoveryKey(rk);
      expect(await VaultKeyring.parseRecoveryKey(code), rk);
    });

    test('items: round trip, tier isolation, no cut-and-paste, sizes hidden', () async {
      final ring = VaultKeyring.create('v1');
      final item = await ItemCrypto.seal(vaultId: 'v1', tier: Tier.secrets,
          tierKey: ring.tierKeys[Tier.secrets]!, itemId: 'i1', plaintext: b('iPhone passcode 123456'));
      expect(await ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!, item: item),
          b('iPhone passcode 123456'));
      // The essentials tier key must not open a secrets item.
      await expectLater(
          ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.essentials]!, item: item), throwsSsb);
      // Claiming it is an essentials item fails too (tier is bound in).
      await expectLater(ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!,
          item: SealedItem('i1', Tier.essentials, item.wrappedItemKey, item.body)), throwsSsb);
      // Moving a body under another item id fails.
      await expectLater(ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!,
          item: SealedItem('i2', Tier.secrets, item.wrappedItemKey, item.body)), throwsSsb);
      // Short items all pad to the same size.
      final tiny = await ItemCrypto.seal(vaultId: 'v1', tier: Tier.secrets,
          tierKey: ring.tierKeys[Tier.secrets]!, itemId: 'i3', plaintext: b('x'));
      expect(tiny.body.length, item.body.length);
    });

    test('tier rotation re-wraps without re-encrypting bodies', () async {
      final ring = VaultKeyring.create('v1');
      final old = Uint8List.fromList(ring.tierKeys[Tier.secrets]!);
      final item = await ItemCrypto.seal(vaultId: 'v1', tier: Tier.secrets,
          tierKey: old, itemId: 'i1', plaintext: b('pw'));
      ring.rotateTier(Tier.secrets);
      final moved = await ItemCrypto.rewrapItemKey(vaultId: 'v1', item: item,
          oldTierKey: old, newTier: Tier.secrets, newTierKey: ring.tierKeys[Tier.secrets]!);
      // Equal bytes, but never the same buffer (SSB-2026-001 follow-up).
      expect(moved.body, equals(item.body));
      expect(identical(moved.body, item.body), isFalse);
      expect(await ItemCrypto.open(vaultId: 'v1', tierKey: ring.tierKeys[Tier.secrets]!, item: moved), b('pw'));
      await expectLater(ItemCrypto.open(vaultId: 'v1', tierKey: old, item: moved), throwsSsb);
    });

    test('files round trip through STREAM', () async {
      final ring = VaultKeyring.create('v1');
      final data = randomBytes(200 * 1024);
      final (wk, stream) = await ItemCrypto.sealFile(vaultId: 'v1', tier: Tier.essentials,
          tierKey: ring.tierKeys[Tier.essentials]!, fileId: 'will.pdf', data: data);
      expect(await ItemCrypto.openFile(vaultId: 'v1', tier: Tier.essentials,
          tierKey: ring.tierKeys[Tier.essentials]!, fileId: 'will.pdf', wrappedKey: wk, stream: stream), data);
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
          tier: Tier.secrets, tierKey: tk, beneficiaryPublicKey: beneficiary.publicKey);
      expect(bundle.beneficiaryKitCode, startsWith('SSB1-BK-'));
      expect(bundle.attorneyKitCode, startsWith('SSB1-AK-'));

      expect(await Release.recoverWithServerShare(vaultId: 'v1', beneficiaryId: 'b1',
          tier: Tier.secrets, beneficiaryKitCode: bundle.beneficiaryKitCode,
          sealedServerShare: bundle.sealedServerShare, beneficiarySecretKey: beneficiary.secretKey), tk);
      expect(await Release.recoverOffline(beneficiaryKitCode: bundle.beneficiaryKitCode,
          attorneyKitCode: bundle.attorneyKitCode), tk);

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
          tier: Tier.secrets, tierKey: randomBytes(32), beneficiaryPublicKey: beneficiary.publicKey);
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
