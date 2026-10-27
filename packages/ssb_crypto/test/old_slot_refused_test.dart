// SSB-2026-002 Phase 1 (M5): a replayed Vault-Key slot (old passphrase wrap)
// is refused -- finding F3.
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

Future<String> outcome(Future<dynamic> Function() f) async {
  try {
    await f();
    return 'OK';
  } on SsbCryptoException catch (e) {
    return 'SSB:${e.message}';
  } catch (e) {
    return 'OTHER:${e.runtimeType}';
  }
}

void main() {
  final kekOld = randomBytes(32), kekNew = randomBytes(32), rk = randomBytes(32);

  test('passphrase change: old slot blob + old key fails under the new manifest (slotHash / epoch)', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kekOld, 'recovery': rk});
    final s1 = await o.write([]);
    expect(s1.slotEpochs, {'unlock': 1, 'recovery': 1});
    // Passphrase change -> new unlock slot at epoch 2.
    await o.setSlot('unlock', kekNew);
    final s2 = await o.write([]);
    expect(s2.slotEpochs['unlock'], 2);
    expect(s2.slotEpochs['recovery'], 1);
    // Honest open with the new passphrase key.
    (await s2.open(kek: kekNew, anchor: anchor)).dispose();
    // Server replays the OLD slot blob with the new cleartext epoch: the AEAD
    // context (epoch 2) does not match the blob (sealed at epoch 1).
    expect(await outcome(() => s2.open(kek: kekOld, anchor: anchor, wrappedVaultKey: s1.wrappedVaultKeys['unlock'])),
        'SSB:decrypt failed');
    // Server replays the old blob AND rolls the cleartext slotEpochs back to
    // 1: the Vault Key opens, but the manifest says the slot is at epoch 2.
    expect(await outcome(() => s2.open(kek: kekOld, anchor: anchor,
        wrappedVaultKey: s1.wrappedVaultKeys['unlock'], slotEpochs: s1.slotEpochs)), 'SSB:stale slot');
    // Server rolls back everything to state 1: the device anchor refuses.
    expect(await outcome(() => s1.open(kek: kekOld, anchor: anchor)), 'SSB:stale manifest');
    // The untouched recovery slot still works against the new manifest.
    (await s2.open(kek: rk, slot: 'recovery', anchor: anchor)).dispose();
  });

  test('a slot re-wrapped at the SAME epoch but not yet in the manifest is refused (hash binds the exact blob)', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kekOld});
    final s1 = await o.write([]);
    // Re-wrap at epoch 1 again (a buggy or malicious client); the manifest on
    // disk still records s1's blob hash.
    final rewrapped = await o.ring.wrapVaultKey(kekOld, slot: 'unlock', epoch: 1);
    expect(await outcome(() => s1.open(kek: kekOld, anchor: anchor, wrappedVaultKey: rewrapped)), 'SSB:stale slot');
    // After the manifest is re-sealed, the new blob is the bound one.
    final s2 = await o.write([]);
    (await s2.open(kek: kekOld, anchor: anchor, wrappedVaultKey: rewrapped)).dispose();
    expect(await outcome(() => s2.open(kek: kekOld, anchor: anchor, wrappedVaultKey: s1.wrappedVaultKeys['unlock'])),
        'SSB:stale slot');
  });

  test('slot epoch bookkeeping: cleartext epoch missing, zero without a legacy record, or out of range', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kekOld});
    final s = await o.write([]);
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, slotEpochs: const {})), 'SSB:stale slot');
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, slotEpochs: const {'unlock': 0})), 'SSB:decrypt failed',
        reason: 'epoch 0 selects the v1 context, which a v2 blob never matches');
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, slotEpochs: const {'unlock': 2})), 'SSB:decrypt failed');
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, slotEpochs: const {'unlock': -1})), 'SSB:stale slot');
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, slotEpochs: const {'unlock': 0x100000000})), 'SSB:stale slot');
    // wrapVaultKey refuses epoch 0 (reserved for v1 wraps) and out-of-range values.
    expect(await outcome(() => o.ring.wrapVaultKey(kekOld, slot: 'unlock', epoch: 0)), 'SSB:bad epoch');
    expect(await outcome(() => o.ring.wrapVaultKey(kekOld, slot: 'unlock', epoch: -1)), 'SSB:bad epoch');
    expect(await outcome(() => o.ring.wrapVaultKey(kekOld, slot: 'unlock', epoch: 0x100000000)), 'SSB:bad epoch');
    expect(o.ring.nextSlotEpoch('unlock'), 2);
    expect(o.ring.nextSlotEpoch('never'), 1);
  });

  test('slot and vault id are still bound (v1 guarantees kept)', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kekOld, 'recovery': rk});
    final s = await o.write([]);
    expect(await outcome(() => s.open(kek: kekOld, slot: 'recovery', anchor: anchor,
        wrappedVaultKey: s.wrappedVaultKeys['unlock'])), 'SSB:decrypt failed');
    expect(await outcome(() => s.open(kek: kekOld, anchor: anchor, vaultId: 'v2')), 'SSB:decrypt failed');
    // v1's B4 ambiguity: (slot "a|vault:b", vault "c") vs (slot "a", vault "b|vault:c").
    final x = await OwnerVault.create('c', anchor: InMemoryAnchor());
    final blob = await x.ring.wrapVaultKey(kekOld, slot: 'a|vault:b', epoch: 1);
    await expectLater(Aead.open(kekOld, blob, type: ObjectType.wrappedKey,
        context: VaultKeyring.vkContext('b|vault:c', 'a', 1)), throwsA(isA<SsbCryptoException>()));
    expect(await Aead.open(kekOld, blob, type: ObjectType.wrappedKey,
        context: VaultKeyring.vkContext('c', 'a|vault:b', 1)), x.ring.vaultKey);
  });

  test('a legacy (epoch 0) slot opens through the v1 context once it is recorded, and is bound by its hash', () async {
    // Simulate the migration (D12): the recovery slot stays a v1 wrap.
    final anchor = InMemoryAnchor();
    final vk = randomBytes(32);
    final v1RecoveryBlob = await _sealV1Vk(vk, rk, 'v', 'recovery');
    final ring = VaultKeyring.adopt(vaultId: 'v', vaultKey: vk, anchor: anchor);
    expect(ring.vaultKey, vk);
    expect(identical(ring.vaultKey, vk), isFalse);
    expect(ring.tierEpochs.values.toSet(), {1});
    ring.recordLegacySlot('recovery', v1RecoveryBlob);
    final o = OwnerVault(ring)..wrappedVaultKeys['recovery'] = v1RecoveryBlob;
    await o.setSlot('unlock', kekNew);
    final s = await o.write([]);
    expect(s.slotEpochs, {'recovery': 0, 'unlock': 1});
    final r = await s.open(kek: rk, slot: 'recovery', anchor: anchor);
    expect(r.slotEpochs['recovery'], 0);
    // First recovery unlock upgrades the slot (what the app does next).
    final up = OwnerVault(r)..wrappedVaultKeys.addAll(s.wrappedVaultKeys);
    await up.setSlot('recovery', rk);
    final s2 = await up.write([]);
    expect(s2.slotEpochs['recovery'], 1);
    (await s2.open(kek: rk, slot: 'recovery', anchor: anchor)).dispose();
    // The old v1 blob is now refused (hash + epoch no longer match).
    expect(await outcome(() => s2.open(kek: rk, slot: 'recovery', anchor: anchor,
        wrappedVaultKey: v1RecoveryBlob, slotEpochs: {...s2.slotEpochs, 'recovery': 0})), 'SSB:stale slot');
    // A different v1 blob for the same key is refused by the hash even at epoch 0.
    final other = await _sealV1Vk(vk, rk, 'v', 'recovery');
    expect(await outcome(() => s.open(kek: rk, slot: 'recovery', anchor: InMemoryAnchor(), wrappedVaultKey: other)), 'SSB:stale slot');
    r.dispose();
  });
}

/// A v1 Vault-Key wrap, exactly as the pre-Phase-1 keyring produced it:
/// header(v1) | nonce | ct | tag, AAD = header(v1) || `ssb/v1/vk/<slot>|vault:<id>`.
Future<Uint8List> _sealV1Vk(Uint8List vk, Uint8List kek, String vaultId, String slot) async {
  final header = buildHeader(ObjectType.wrappedKey, formatVersion: 1);
  final nonce = randomBytes(12);
  final box = await AesGcm.with256bits().encrypt(vk,
      secretKey: SecretKeyData(kek), nonce: nonce,
      aad: concatBytes([header, VaultKeyring.legacyVkContext(vaultId, slot)]));
  return concatBytes([header, nonce, box.cipherText, box.mac.bytes]);
}
