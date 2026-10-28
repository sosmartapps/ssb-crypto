// Regression for SSB-2026-004 (reported 2026-10-25 against public mirror
// a7f304f): the item/file key-wrap AAD
// 'ssb/v1/ik|vault:$vaultId|tier:$tier|item:$itemId' had no length prefixes, so
//
//   A = (vaultId 'V|tier:ice|item:B', itemId 'C')
//   B = (vaultId 'V',                 itemId 'B|tier:ice|item:C')
//
// gave identical AAD and a wrapped item/file key sealed under A opened under B.
// Format v2 builds every context with ctx2 (length-prefixed). These tests seal
// under A and require EVERY v2 entry point to refuse B, and vice versa, for
// all nine (tier, tier) shapes of the collision, items and files, and the
// epoch dimension as well.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

void main() {
  const aV = 'V|tier:ice|item:B', aI = 'C';
  const bV = 'V', bI = 'B|tier:ice|item:C';
  late Uint8List tk, tk2;

  setUp(() {
    tk = randomBytes(32);
    tk2 = randomBytes(32);
  });

  test('the colliding tuples really are distinct v2 inputs with distinct contexts', () {
    expect(ItemCrypto.keyContext(aV, Tier.ice, 1, aI), isNot(equals(ItemCrypto.keyContext(bV, Tier.ice, 1, bI))));
    expect(ItemCrypto.bodyContext(aV, aI), isNot(equals(ItemCrypto.bodyContext(bV, bI))));
    expect(ItemCrypto.fileContext(aV, aI), isNot(equals(ItemCrypto.fileContext(bV, bI))));
  });

  test('the report: the wrapped item key sealed under A does not unwrap under B (and not the reverse)', () async {
    final sA = await ItemCrypto.seal(
        vaultId: aV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: aI, plaintext: bytes('secret A'));
    await expectLater(
        Aead.open(tk, sA.wrappedItemKey,
            type: ObjectType.wrappedKey, context: ItemCrypto.keyContext(bV, Tier.ice, 1, bI)),
        throwsSsb);
    // control: its own tuple unwraps
    final ik = await Aead.open(tk, sA.wrappedItemKey,
        type: ObjectType.wrappedKey, context: ItemCrypto.keyContext(aV, Tier.ice, 1, aI));
    expect(ik.length, 32);

    final sB = await ItemCrypto.seal(
        vaultId: bV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: bI, plaintext: bytes('secret B'));
    await expectLater(
        Aead.open(tk, sB.wrappedItemKey,
            type: ObjectType.wrappedKey, context: ItemCrypto.keyContext(aV, Tier.ice, 1, aI)),
        throwsSsb);
  });

  test('ItemCrypto.open refuses the item re-labelled to the colliding tuple, both directions', () async {
    final sA = await ItemCrypto.seal(
        vaultId: aV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: aI, plaintext: bytes('secret A'));
    expect(await ItemCrypto.open(vaultId: aV, tierKey: tk, tierEpoch: 1, item: sA), bytes('secret A'));
    final relabelled = SealedItem(bI, Tier.ice, sA.wrappedItemKey, sA.body);
    await expectLater(ItemCrypto.open(vaultId: bV, tierKey: tk, tierEpoch: 1, item: relabelled), throwsSsb);

    final sB = await ItemCrypto.seal(
        vaultId: bV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: bI, plaintext: bytes('secret B'));
    final back = SealedItem(aI, Tier.ice, sB.wrappedItemKey, sB.body);
    await expectLater(ItemCrypto.open(vaultId: aV, tierKey: tk, tierEpoch: 1, item: back), throwsSsb);
  });

  test('rewrapItemKey refuses to move an item key across the colliding tuples', () async {
    final sA = await ItemCrypto.seal(
        vaultId: aV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: aI, plaintext: bytes('secret A'));
    final relabelled = SealedItem(bI, Tier.ice, sA.wrappedItemKey, sA.body);
    await expectLater(
        ItemCrypto.rewrapItemKey(
            vaultId: bV, item: relabelled, oldTierKey: tk, oldTierEpoch: 1,
            newTier: Tier.ice, newTierKey: tk2, newTierEpoch: 2),
        throwsSsb);
    // control: the legitimate rewrap works and the result opens under the new epoch only
    final moved = await ItemCrypto.rewrapItemKey(
        vaultId: aV, item: sA, oldTierKey: tk, oldTierEpoch: 1,
        newTier: Tier.ice, newTierKey: tk2, newTierEpoch: 2);
    expect(await ItemCrypto.open(vaultId: aV, tierKey: tk2, tierEpoch: 2, item: moved), bytes('secret A'));
    await expectLater(ItemCrypto.open(vaultId: aV, tierKey: tk2, tierEpoch: 1, item: moved), throwsSsb);
  });

  test('sealFile / openFile: the file key and stream do not open under the colliding tuple', () async {
    final data = bytes('file bytes ' * 50);
    final (wk, stream) = await ItemCrypto.sealFile(
        vaultId: aV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: aI, data: data);
    await expectLater(
        ItemCrypto.openFile(
            vaultId: bV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: bI,
            wrappedKey: wk, stream: stream),
        throwsSsb);
    // the wrap alone, as in the report
    await expectLater(
        Aead.open(tk, wk, type: ObjectType.wrappedKey, context: ItemCrypto.keyContext(bV, Tier.ice, 1, bI)),
        throwsSsb);
    // control
    expect(
        await ItemCrypto.openFile(
            vaultId: aV, tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: aI,
            wrappedKey: wk, stream: stream),
        data);
  });

  test('every (tier, tier) shape of the collision is refused: V|tier:T1|item:X / T2 / Y  vs  V / T1 / X|tier:T2|item:Y', () async {
    for (final t1 in Tier.values) {
      for (final t2 in Tier.values) {
        final aVault = 'V|tier:${t1.name}|item:X', bItem = 'X|tier:${t2.name}|item:Y';
        final s = await ItemCrypto.seal(
            vaultId: aVault, tier: t2, tierKey: tk, tierEpoch: 3, itemId: 'Y', plaintext: bytes('p'));
        final moved = SealedItem(bItem, t1, s.wrappedItemKey, s.body);
        await expectLater(ItemCrypto.open(vaultId: 'V', tierKey: tk, tierEpoch: 3, item: moved), throwsSsb,
            reason: '${t1.name}/${t2.name}');
        await expectLater(
            ItemCrypto.rewrapItemKey(
                vaultId: 'V', item: moved, oldTierKey: tk, oldTierEpoch: 3,
                newTier: t1, newTierKey: tk2, newTierEpoch: 4),
            throwsSsb,
            reason: 'rewrap ${t1.name}/${t2.name}');
      }
    }
  });

  test('tier-key, vault-key slot and tier-export wraps also separate delimiter-laden ids', () async {
    // The same shape in the other wraps (audit B4 sibling): slot / vault ids.
    final kek = randomBytes(32), vk = randomBytes(32);
    final blob = await Aead.seal(kek, vk,
        type: ObjectType.wrappedKey, context: VaultKeyring.vkContext('c', 'a|vault:b', 1));
    await expectLater(
        Aead.open(kek, blob,
            type: ObjectType.wrappedKey, context: VaultKeyring.vkContext('b|vault:c', 'a', 1)),
        throwsSsb);
    final export = await TierExportCrypto.seal(
        vaultId: 'V|tier:essentials', tier: Tier.secrets, tierKey: tk, epoch: 1, seq: 1,
        prevHash: TierExportCrypto.genesisPrevHash, plaintext: bytes('bundle'));
    await expectLater(
        TierExportCrypto.open(
            vaultId: 'V', tier: Tier.essentials, tierKey: tk, header: export.header,
            ciphertext: export.ciphertext),
        throwsSsb);
  });

  test('epoch is part of the binding: 2^32 does not alias epoch 0, -1 does not alias 2^32-1', () async {
    // u32be used to truncate silently (epoch 4294967296 encoded like 0).
    final s = await ItemCrypto.seal(
        vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 0, itemId: 'i', plaintext: bytes('p'));
    await expectLater(ItemCrypto.open(vaultId: 'v', tierKey: tk, tierEpoch: 0x100000000, item: s), throwsSsb);
    final s2 = await ItemCrypto.seal(
        vaultId: 'v', tier: Tier.ice, tierKey: tk, tierEpoch: 0xffffffff, itemId: 'i', plaintext: bytes('p'));
    await expectLater(ItemCrypto.open(vaultId: 'v', tierKey: tk, tierEpoch: -1, item: s2), throwsSsb);
    expect(await ItemCrypto.open(vaultId: 'v', tierKey: tk, tierEpoch: 0, item: s), bytes('p'));
  });
}
