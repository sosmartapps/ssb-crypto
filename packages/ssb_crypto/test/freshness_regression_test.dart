// SSB-2026-002 regression suite: the seven freshness proofs-of-concept
// reported 2026-10-20, converted to tests. Each one RAN GREEN as an
// attack against format v1; here the same attack must FAIL against format v2.
//
//   F4  tier-key wrap replay after rotateTier()        -> refused (two ways)
//   F3  old passphrase slot replay                     -> refused
//   F2a item edit rollback (pre-edit SealedItem)       -> refused (itemsHash)
//   F2b pre-rewrap item readable under the old key     -> refused under the current keyring
//   F1  old S1 + old S2 after rotation                 -> generation mismatch is detectable
//   F5  signature freshness                            -> documented behaviour (Phase 2)
//   F6  static claim / owner tokens                    -> documented behaviour (Phase 2)
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());
String s(Uint8List x) => String.fromCharCodes(x);

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
  const vault = 'v1';
  final muk = randomBytes(32);

  test('F4 (the report): rotateTier is NOT undone when the server replays pre-rotation wraps', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create(vault, anchor: anchor, keks: {'unlock': muk});
    // S0: server snapshot BEFORE rotation.
    final oldKey = Uint8List.fromList(o.ring.tierKey(Tier.secrets));
    final item1 = await o.sealItem(Tier.secrets, 'i1', 'before');
    final s0 = await o.write([item1]);
    // Owner removes a beneficiary and rotates; client re-wraps and uploads S1.
    o.ring.rotateTier(Tier.secrets);
    final newKey = Uint8List.fromList(o.ring.tierKey(Tier.secrets));
    expect(newKey, isNot(oldKey));
    final items1 = await o.rewrapAfterRotation([item1], Tier.secrets, oldKey, 1);
    final s1 = await o.write(items1);
    // Honest unlock with S1 gets the NEW key.
    final honest = await s1.open(kek: muk, anchor: anchor);
    expect(honest.tierKey(Tier.secrets), newKey);
    expect(honest.tierEpoch(Tier.secrets), 2);
    honest.dispose();

    // ATTACK A: malicious server replays S0's tier wraps under the current
    // manifest. The wraps were sealed at epoch 1; the manifest says 2.
    expect(await outcome(() => s1.open(kek: muk, anchor: anchor, tiers: s0.tiers)), 'SSB:decrypt failed');
    // ...also with S0's items (so itemsHash would match S0): still the wraps fail first.
    expect(await outcome(() => s1.open(kek: muk, anchor: anchor, tiers: s0.tiers, items: s0.items)), 'SSB:decrypt failed');

    // ATTACK B: the server replays ALL of S0 (manifest included). The device
    // anchor has seen seq 2.
    expect(await outcome(() => s0.open(kek: muk, anchor: anchor)), 'SSB:stale manifest');
    // Same through the biometric path.
    expect(await outcome(() => s0.openWithVaultKey(vaultKey: o.ring.vaultKey, anchor: anchor)), 'SSB:stale manifest');

    // Nobody got the old key back, so no new item can be sealed under it by
    // an honest client, and the removed beneficiary's key reads nothing new.
    final item2 = await o.sealItem(Tier.secrets, 'i2', 'after-removal');
    await expectLater(ItemCrypto.open(vaultId: vault, tierKey: oldKey, tierEpoch: 1, item: item2), throwsSsb);
    await expectLater(ItemCrypto.open(vaultId: vault, tierKey: oldKey, tierEpoch: 2, item: item2), throwsSsb);
    expect(s(await o.openItem(item2)), 'after-removal');
  });

  test('F3 slot replay: after a passphrase change the old unlock slot no longer opens the vault', () async {
    final anchor = InMemoryAnchor();
    final kekOld = randomBytes(32), kekNew = randomBytes(32); // stand-ins for Argon2 outputs
    final o = await OwnerVault.create(vault, anchor: anchor, keks: {'unlock': kekOld});
    final before = await o.write([]);
    await o.setSlot('unlock', kekNew); // passphrase changed; server should replace the slot
    final after = await o.write([]);
    final honest = await after.open(kek: kekNew, anchor: anchor);
    expect(honest.vaultKey, o.ring.vaultKey);
    honest.dispose();
    // Server replays the old slot (and, to get past the AEAD, the old cleartext epoch).
    expect(await outcome(() => after.open(kek: kekOld, anchor: anchor,
        wrappedVaultKey: before.wrappedVaultKeys['unlock'])), 'SSB:decrypt failed');
    expect(await outcome(() => after.open(kek: kekOld, anchor: anchor,
        wrappedVaultKey: before.wrappedVaultKeys['unlock'], slotEpochs: before.slotEpochs)), 'SSB:stale slot');
    expect(await outcome(() => before.open(kek: kekOld, anchor: anchor)), 'SSB:stale manifest');
  });

  test('F2a item edit rollback: the pre-edit SealedItem is refused by the manifest itemsHash', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create(vault, anchor: anchor, keks: {'unlock': muk});
    final v1 = await o.sealItem(Tier.secrets, 'i1', 'password=OLD');
    final st1 = await o.write([v1]);
    final v2 = await o.sealItem(Tier.secrets, 'i1', 'password=NEW');
    final st2 = await o.write([v2]);
    // Honest.
    final r = await st2.open(kek: muk, anchor: anchor);
    expect(s(await o.openItem(v2)), 'password=NEW');
    r.dispose();
    // Server serves the pre-edit item with the current manifest.
    expect(await outcome(() => st2.open(kek: muk, anchor: anchor, items: [v1])), 'SSB:items do not match manifest');
    // Server serves the pre-edit item set AND the pre-edit manifest.
    expect(await outcome(() => st1.open(kek: muk, anchor: anchor)), 'SSB:stale manifest');
    // Deleting an item is a write too: an item that reappears is refused.
    final st3 = await o.write([]);
    expect(await outcome(() => st3.open(kek: muk, anchor: anchor, items: [v2])), 'SSB:items do not match manifest');
    (await st3.open(kek: muk, anchor: anchor)).dispose();
    // The raw primitive still opens the old ciphertext under its old key
    // (ciphertext cannot be unsent); what changed is that the keyring never
    // accepts the set it belongs to. Mixed old wrap + new body is caught as before.
    expect(s(await ItemCrypto.open(vaultId: vault, tierKey: o.ring.tierKey(Tier.secrets), tierEpoch: 1, item: v1)), 'password=OLD');
    await expectLater(ItemCrypto.open(vaultId: vault, tierKey: o.ring.tierKey(Tier.secrets), tierEpoch: 1,
        item: SealedItem('i1', Tier.secrets, v1.wrappedItemKey, v2.body)), throwsSsb);
  });

  test('F2b pre-rewrap item: stale item is refused under the current epoch and by the manifest', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create(vault, anchor: anchor, keks: {'unlock': muk});
    final oldKey = Uint8List.fromList(o.ring.tierKey(Tier.secrets));
    final it0 = await o.sealItem(Tier.secrets, 'i9', 'secret');
    final st0 = await o.write([it0]);
    o.ring.rotateTier(Tier.secrets);
    final it1 = (await o.rewrapAfterRotation([it0], Tier.secrets, oldKey, 1)).single;
    final st1 = await o.write([it1]);
    // Honest: it1 under the new key/epoch works.
    expect(s(await o.openItem(it1)), 'secret');
    // The current keyring (epoch 2) refuses the stale item outright.
    await expectLater(o.openItem(it0), throwsSsb);
    // Even the removed beneficiary's old key cannot pass it off as current:
    // under the current epoch context the wrap fails.
    await expectLater(ItemCrypto.open(vaultId: vault, tierKey: oldKey, tierEpoch: 2, item: it0), throwsSsb);
    // The old key + old epoch still reads the old ciphertext (inherent), but
    // the vault as a whole will not accept it0 as part of its state:
    expect(s(await ItemCrypto.open(vaultId: vault, tierKey: oldKey, tierEpoch: 1, item: it0)), 'secret');
    expect(await outcome(() => st1.open(kek: muk, anchor: anchor, items: [it0])), 'SSB:items do not match manifest');
    expect(await outcome(() => st0.open(kek: muk, anchor: anchor)), 'SSB:stale manifest');
  });

  test('F1 S2 replay: old S1 + replayed old S2 is recognisable as an older generation', () async {
    final ben = await XWing.generateKeyPair();
    final oldKey = randomBytes(32);
    final b0 = await Release.create(vaultId: vault, beneficiaryId: 'B', tier: Tier.secrets,
        tierKey: oldKey, beneficiaryPublicKey: ben.publicKey, epoch: 1);
    // Owner rotates tier (epoch 2) and issues a NEW bundle; an honest server replaces S2.
    final newKey = randomBytes(32);
    final b1 = await Release.create(vaultId: vault, beneficiaryId: 'B', tier: Tier.secrets,
        tierKey: newKey, beneficiaryPublicKey: ben.publicKey, epoch: 2);
    // Malicious server keeps / serves the OLD S2 against the old kit. The
    // ciphertext cannot be unsent, so the old key comes back -- but stamped
    // with its generation, and the server's own tier doc now says epoch 2.
    final got = await Release.recoverWithServerShare(vaultId: vault, beneficiaryId: 'B', tier: Tier.secrets,
        beneficiaryKitCode: b0.beneficiaryKitCode, sealedServerShare: b0.sealedServerShare,
        beneficiarySecretKey: ben.secretKey);
    expect(got.key, oldKey);
    expect(got.epoch, 1);
    expect(b1.epoch, 2);
    // What the app does with that (design D11): the kit's epoch is readable
    // alone, and when the server reports the current epoch the mismatch is
    // named before anything is opened.
    expect(await Release.kitEpoch(b0.beneficiaryKitCode), 1);
    expect(await outcome(() => Release.recoverWithServerShare(vaultId: vault, beneficiaryId: 'B', tier: Tier.secrets,
        beneficiaryKitCode: b0.beneficiaryKitCode, sealedServerShare: b1.sealedServerShare,
        beneficiarySecretKey: ben.secretKey, serverShareEpoch: 2)), 'SSB:${Release.olderGeneration}');
    // Mixed generations never yield a key, with or without the server's hint.
    expect(await outcome(() => Release.recoverWithServerShare(vaultId: vault, beneficiaryId: 'B', tier: Tier.secrets,
        beneficiaryKitCode: b1.beneficiaryKitCode, sealedServerShare: b0.sealedServerShare,
        beneficiarySecretKey: ben.secretKey)), 'SSB:decrypt failed');
    // And the old key opens no current export: epoch is in the export AAD.
    final e = await TierExportCrypto.seal(vaultId: vault, tier: Tier.secrets, tierKey: newKey, epoch: 2, seq: 1,
        prevHash: TierExportCrypto.genesisPrevHash, plaintext: bytes('x'));
    await expectLater(TierExportCrypto.open(vaultId: vault, tier: Tier.secrets, tierKey: got.key,
        header: e.header, ciphertext: e.ciphertext), throwsSsb);
  });

  test('F5 (documented behaviour, Phase 2): HybridSignature has no freshness of its own', () async {
    // Unchanged by design in Phase 1 (design D14): a signature over identical
    // bytes verifies forever. Freshness MUST come from the signed message
    // (sequence / nonce / timestamp), which Phase 2's owner-signed manifest
    // head and client-verified audit chain provide. This test pins the
    // contract so that a future change is deliberate.
    final kp = await HybridSignature.generateKeyPair();
    final msg = bytes('release vault=v1 beneficiary=B');
    final sig = await HybridSignature.sign(kp.secretKey, msg, purpose: 'ssb/release');
    expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: 'ssb/release'), isTrue);
    expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: 'ssb/release'), isTrue);
    // ...but a message that carries its own sequence is not replayable as another:
    final seq1 = bytes('release vault=v1 beneficiary=B seq=1');
    final sig1 = await HybridSignature.sign(kp.secretKey, seq1, purpose: 'ssb/release');
    expect(await HybridSignature.verify(kp.publicKey, bytes('release vault=v1 beneficiary=B seq=2'), sig1, purpose: 'ssb/release'), isFalse);
  });

  test('F6 (documented behaviour, Phase 2): claim / owner tokens are deterministic', () async {
    // Unchanged by design in Phase 1 (design D14): the tokens are stable
    // identifiers (they must survive a phone loss), so capture = replay
    // against the server. Phase 2 adds session revocation and per-request freshness.
    final sk = randomBytes(32);
    expect(await ClaimToken.compute(beneficiarySecretKey: sk), await ClaimToken.compute(beneficiarySecretKey: sk));
    expect(await OwnerToken.compute(vaultId: vault, vaultKey: sk), await OwnerToken.compute(vaultId: vault, vaultKey: sk));
    // What IS guaranteed: a leaked verifier never yields a token, and the two
    // domains never collide.
    final t = await ClaimToken.compute(beneficiarySecretKey: sk);
    expect(await ClaimToken.verifier(t), isNot(t));
    expect(await OwnerToken.compute(vaultId: vault, vaultKey: sk), isNot(t));
  });
}
