// SSB-2026-002 Phase 1 (M5): `package:ssb_crypto/legacy_v1.dart` opens
// format-v1 objects built exactly as the pre-Phase-1 package produced them,
// and the v2 API refuses every one of them. This is what the v1 -> v2
// migration (design D12) and the transitional claim path rely on.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/legacy_v1.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());
Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));

/// v1 `Aead.seal`: header(v1) | nonce | ct | tag, AAD = header(v1) || ctx.
Future<Uint8List> sealV1(Uint8List key, Uint8List pt, ObjectType type, List<int> ctx) async {
  final header = buildHeader(type, formatVersion: 1);
  final nonce = randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(pt,
      secretKey: SecretKeyData(key), nonce: nonce, aad: concatBytes([header, ctx]));
  return concatBytes([header, nonce, box.cipherText, box.mac.bytes]);
}

/// v1 `_pad`: len(4) | data | zeros to the Padmé bucket (min 256).
Uint8List padV1(Uint8List data) {
  final n = data.length + 4;
  final target = ItemCrypto.padmeLength(n < 256 ? 256 : n);
  return Uint8List(target)..setAll(0, u32be(data.length))..setAll(4, data);
}

/// Reference GF(2^8) multiply (AES polynomial), for building v1 shares by hand.
int gmul(int a, int b) {
  var p = 0;
  while (b > 0) {
    if (b & 1 == 1) p ^= a;
    a <<= 1;
    if (a & 0x100 != 0) a ^= 0x11b;
    b >>= 1;
  }
  return p;
}

/// v1 `Shamir.split` 2-of-3: version 1 | threshold 2 | x | keyCheck(8) | y(32),
/// keyCheck = HKDF-SHA384(secret, salt='', 'ssb/v1/share-check')[:8].
Future<List<Uint8List>> splitV1(Uint8List secret) async {
  final check = await hkdfSha384(ikm: secret, salt: const [], info: 'ssb/v1/share-check', length: 8);
  final c = randomBytes(secret.length);
  return [
    for (var x = 1; x <= 3; x++)
      concatBytes([[1, 2, x], check, [for (var i = 0; i < secret.length; i++) secret[i] ^ gmul(c[i], x)]])
  ];
}

void main() {
  const vaultId = 'v1-vault';

  group('v1 keyring and items open through legacy_v1 only', () {
    late Uint8List vk, kek, rk, wvkUnlock, wvkRecovery;
    late Map<Tier, Uint8List> tks, wtks;
    late SealedItem item;
    late Uint8List fileWk, fileStream;

    setUpAll(() async {
      vk = randomBytes(32);
      kek = randomBytes(32);
      rk = randomBytes(32);
      tks = {for (final t in Tier.values) t: randomBytes(32)};
      wvkUnlock = await sealV1(kek, vk, ObjectType.wrappedKey, utf8Bytes('ssb/v1/vk/unlock|vault:$vaultId'));
      wvkRecovery = await sealV1(rk, vk, ObjectType.wrappedKey, utf8Bytes('ssb/v1/vk/recovery|vault:$vaultId'));
      wtks = {
        for (final t in Tier.values)
          t: await sealV1(vk, tks[t]!, ObjectType.wrappedKey, utf8Bytes('ssb/v1/tk/${t.name}|vault:$vaultId'))
      };
      final ik = randomBytes(32);
      item = SealedItem('i1', Tier.secrets,
          await sealV1(tks[Tier.secrets]!, ik, ObjectType.wrappedKey, utf8Bytes('ssb/v1/ik|vault:$vaultId|tier:secrets|item:i1')),
          await sealV1(ik, padV1(b('old item')), ObjectType.item, utf8Bytes('ssb/v1/item|vault:$vaultId|item:i1')));
      // v1 file: wrapped file key + one-chunk v1 STREAM.
      final fk = randomBytes(32);
      fileWk = await sealV1(tks[Tier.essentials]!, fk, ObjectType.wrappedKey, utf8Bytes('ssb/v1/ik|vault:$vaultId|tier:essentials|item:f1'));
      final padded = padV1(b('file bytes'));
      final head = concatBytes([buildHeader(ObjectType.fileStream, formatVersion: 1), randomBytes(7), u32be(65536)]);
      final box = await AesGcm.with256bits().encrypt(padded,
          secretKey: SecretKeyData(fk), nonce: concatBytes([head.sublist(6, 13), u32be(0), [1]]),
          aad: concatBytes([head, utf8Bytes('ssb/v1/item|vault:$vaultId|item:f1')]));
      fileStream = concatBytes([head, box.cipherText, box.mac.bytes]);
    });

    test('VaultKeyringV1.open / fromVaultKey yield the v1 keys; the v2 keyring refuses the same objects', () async {
      final a = await VaultKeyringV1.open(vaultId: vaultId, kek: kek, slot: 'unlock', wrappedVaultKey: wvkUnlock, wrappedTierKeys: wtks);
      expect(a.vaultKey, vk);
      expect(a.tierKey(Tier.secrets), tks[Tier.secrets]);
      final c = await VaultKeyringV1.open(vaultId: vaultId, kek: rk, slot: 'recovery', wrappedVaultKey: wvkRecovery, wrappedTierKeys: wtks);
      expect(c.vaultKey, vk);
      final f = await VaultKeyringV1.fromVaultKey(vaultId: vaultId, vaultKey: vk, wrappedTierKeys: wtks);
      expect(f.tierKeys, tks);
      // Still bound: slot, vault id, partial map, wrong kek.
      await expectLater(VaultKeyringV1.open(vaultId: vaultId, kek: kek, slot: 'recovery', wrappedVaultKey: wvkUnlock, wrappedTierKeys: wtks), throwsSsb);
      await expectLater(VaultKeyringV1.open(vaultId: 'other', kek: kek, slot: 'unlock', wrappedVaultKey: wvkUnlock, wrappedTierKeys: wtks), throwsSsb);
      await expectLater(VaultKeyringV1.open(vaultId: vaultId, kek: kek, slot: 'unlock', wrappedVaultKey: wvkUnlock, wrappedTierKeys: {Tier.ice: wtks[Tier.ice]!}), throwsSsb);
      await expectLater(VaultKeyringV1.fromVaultKey(vaultId: vaultId, vaultKey: Uint8List(32), wrappedTierKeys: wtks), throwsSsb);
      // The v2 primitives never open v1 wraps, whatever epoch is claimed.
      for (final e in [0, 1, 2]) {
        await expectLater(Aead.open(kek, wvkUnlock, type: ObjectType.wrappedKey, context: VaultKeyring.vkContext(vaultId, 'unlock', e)), throwsSsb);
        await expectLater(Aead.open(vk, wtks[Tier.ice]!, type: ObjectType.wrappedKey, context: VaultKeyring.tkContext(vaultId, Tier.ice, e)), throwsSsb);
      }
      await expectLater(Aead.open(kek, wvkUnlock, type: ObjectType.wrappedKey, context: VaultKeyring.legacyVkContext(vaultId, 'unlock')), throwsSsb);
      a.dispose();
      expect(isAllZero(a.vaultKey), isTrue);
      c.dispose();
      f.dispose();
    });

    test('ItemCryptoV1.open / openFile read v1 items and files; v2 ItemCrypto refuses them', () async {
      expect(await ItemCryptoV1.open(vaultId: vaultId, tierKey: tks[Tier.secrets]!, item: item), b('old item'));
      await expectLater(ItemCryptoV1.open(vaultId: vaultId, tierKey: tks[Tier.ice]!, item: item), throwsSsb);
      await expectLater(ItemCryptoV1.open(vaultId: 'other', tierKey: tks[Tier.secrets]!, item: item), throwsSsb);
      for (final e in [0, 1]) {
        await expectLater(ItemCrypto.open(vaultId: vaultId, tierKey: tks[Tier.secrets]!, tierEpoch: e, item: item), throwsSsb);
      }
      expect(await ItemCryptoV1.openFile(vaultId: vaultId, tier: Tier.essentials, tierKey: tks[Tier.essentials]!,
          fileId: 'f1', wrappedKey: fileWk, stream: fileStream), b('file bytes'));
      await expectLater(ItemCrypto.openFile(vaultId: vaultId, tier: Tier.essentials, tierKey: tks[Tier.essentials]!, tierEpoch: 1,
          fileId: 'f1', wrappedKey: fileWk, stream: fileStream), throwsSsb);
    });

    test('migration shape (D12): adopt the Vault Key, re-seal under epoch 1, keep the v1 recovery slot at epoch 0', () async {
      final legacy = await VaultKeyringV1.open(vaultId: vaultId, kek: kek, slot: 'unlock', wrappedVaultKey: wvkUnlock, wrappedTierKeys: wtks);
      final anchor = InMemoryAnchor();
      final ring = VaultKeyring.adopt(vaultId: vaultId, vaultKey: legacy.vaultKey, anchor: anchor);
      final pt = await ItemCryptoV1.open(vaultId: vaultId, tierKey: legacy.tierKey(item.tier), item: item);
      final v2item = await ItemCrypto.seal(vaultId: vaultId, tier: item.tier, tierKey: ring.tierKey(item.tier),
          tierEpoch: ring.tierEpoch(item.tier), itemId: item.itemId, plaintext: pt);
      legacy.dispose();
      final newKek = randomBytes(32);
      final wUnlock2 = await ring.wrapVaultKey(newKek, slot: 'unlock', epoch: 1);
      ring.recordLegacySlot('recovery', wvkRecovery);
      final tiers = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
      final manifest = await ring.sealManifest(items: [v2item]);
      await ring.commitManifest();
      expect(ring.slotEpochs, {'unlock': 1, 'recovery': 0});
      // Passphrase path, v2.
      final r1 = await VaultKeyring.open(vaultId: vaultId, kek: newKek, slot: 'unlock', wrappedVaultKey: wUnlock2,
          slotEpochs: ring.slotEpochs, manifestBlob: manifest, wrappedTierKeys: tiers, items: [v2item], anchor: anchor);
      expect(await ItemCrypto.open(vaultId: vaultId, tierKey: r1.tierKey(Tier.secrets), tierEpoch: r1.tierEpoch(Tier.secrets), item: v2item), b('old item'));
      r1.dispose();
      // Recovery Key path through the untouched v1 slot (epoch 0), bound by its hash.
      final r2 = await VaultKeyring.open(vaultId: vaultId, kek: rk, slot: 'recovery', wrappedVaultKey: wvkRecovery,
          slotEpochs: ring.slotEpochs, manifestBlob: manifest, wrappedTierKeys: tiers, items: [v2item], anchor: anchor);
      expect(r2.vaultKey, vk);
      r2.dispose();
      // The old v1 unlock slot is dead: not in the manifest.
      await expectLater(VaultKeyring.open(vaultId: vaultId, kek: kek, slot: 'unlock', wrappedVaultKey: wvkUnlock,
          slotEpochs: {...ring.slotEpochs, 'unlock': 0}, manifestBlob: manifest, wrappedTierKeys: tiers, items: [v2item], anchor: anchor), throwsSsb);
      // And the old v1 item is not part of the vault any more.
      await expectLater(VaultKeyring.open(vaultId: vaultId, kek: newKek, slot: 'unlock', wrappedVaultKey: wUnlock2,
          slotEpochs: ring.slotEpochs, manifestBlob: manifest, wrappedTierKeys: tiers, items: [item], anchor: anchor), throwsSsb);
    });
  });

  group('v1 kits and tier exports', () {
    late XWingKeyPair ben;
    setUpAll(() async => ben = await XWing.generateKeyPair());

    test('ReleaseV1 recovers a v1 kit (SSB1-BK, 43-byte shares); Release (v2) refuses it', () async {
      final tk = randomBytes(32);
      final sh = await splitV1(tk);
      expect(sh[0].length, 43);
      final s1 = await KitCode.encode('SSB1-BK', sh[0]);
      final s3 = await KitCode.encode('SSB1-AK', sh[2]);
      final s2 = await Hpke.seal(ben.publicKey, sh[1], info: ReleaseV1.s2Info('v', 'B', Tier.secrets));
      expect(s1, startsWith('SSB1-BK-'));
      expect(s1.substring(8).replaceAll('-', '').length, 76); // (43+4)*8/5
      expect(await ReleaseV1.recoverOffline(beneficiaryKitCode: s1, attorneyKitCode: s3), tk);
      expect(await ReleaseV1.recoverWithServerShare(vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets,
          beneficiaryKitCode: s1, sealedServerShare: s2, beneficiarySecretKey: ben.secretKey), tk);
      await expectLater(ReleaseV1.recoverWithServerShare(vaultId: 'v', beneficiaryId: 'C', tier: Tier.secrets,
          beneficiaryKitCode: s1, sealedServerShare: s2, beneficiarySecretKey: ben.secretKey), throwsSsb);
      // v2 never accepts a v1 kit, and a v1 share never parses as v2.
      await expectLater(Release.recoverOffline(beneficiaryKitCode: s1, attorneyKitCode: s3), throwsSsb);
      await expectLater(Release.kitEpoch(s1), throwsSsb);
      expect(() => Share.fromBytes(sh[0]), throwsSsb);
      expect(ShareV1.fromBytes(sh[0]).x, 1);
      // ...and a v2 kit never passes as v1.
      final v2 = await Release.create(vaultId: 'v', beneficiaryId: 'B', tier: Tier.secrets, tierKey: tk,
          beneficiaryPublicKey: ben.publicKey, epoch: 1);
      await expectLater(ReleaseV1.recoverOffline(beneficiaryKitCode: v2.beneficiaryKitCode, attorneyKitCode: v2.attorneyKitCode), throwsSsb);
    });

    test('TierExportV1.open reads the v1 export; TierExportCrypto refuses it', () async {
      final tk = randomBytes(32);
      final bundle = b('{"v":1,"items":[]}');
      final ct = await sealV1(tk, bundle, ObjectType.item, utf8Bytes('ssb/v1/tier-export|vault:v|tier:secrets'));
      expect(await TierExportV1.open(vaultId: 'v', tier: Tier.secrets, tierKey: tk, ciphertext: ct), bundle);
      await expectLater(TierExportV1.open(vaultId: 'v', tier: Tier.ice, tierKey: tk, ciphertext: ct), throwsSsb);
      await expectLater(TierExportCrypto.open(vaultId: 'v', tier: Tier.secrets, tierKey: tk,
          header: TierExportHeader(epoch: 0, seq: 0, prevHash: Uint8List(32)), ciphertext: ct), throwsSsb);
    });
  });
}
