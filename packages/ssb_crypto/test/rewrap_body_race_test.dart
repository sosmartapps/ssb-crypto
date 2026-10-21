// Regression tests for the follow-up to SSB-2026-001 (reported by Ibnu,
// 2026-10-20): ItemCrypto.rewrapItemKey (and ItemCrypto.open) read item.body
// AFTER their first await. Dart runs an async body synchronously up to its
// first await, so `rewrapItemKey(...)` followed by `wipe(item.body)` with no
// await in between wiped the body before the old code ever copied it: the
// re-wrap "succeeded" and returned a new SealedItem whose body was the wiped
// bytes, an item that was permanently corrupted and only failed at the next
// open, as a generic decrypt error.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('item body is snapshotted before the first await', () {
    test('control: rewrap with no concurrent wipe opens normally', () async {
      final tk1 = randomBytes(32), tk2 = randomBytes(32);
      final item = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk1, itemId: 'i', plaintext: utf8Bytes('hello'));
      final re = await ItemCrypto.rewrapItemKey(
          vaultId: 'v', item: item, oldTierKey: tk1, newTier: Tier.ice, newTierKey: tk2);
      expect(await ItemCrypto.open(vaultId: 'v', tierKey: tk2, item: re), equals(utf8Bytes('hello')));
    });

    test('rewrapItemKey: wiping the old body mid-flight does not corrupt the new item', () async {
      for (var trial = 0; trial < 20; trial++) {
        final tk1 = randomBytes(32), tk2 = randomBytes(32);
        final item = await ItemCrypto.seal(
            vaultId: 'v', tier: Tier.ice, tierKey: tk1, itemId: 'i', plaintext: utf8Bytes('hello'));
        final pending = ItemCrypto.rewrapItemKey(
            vaultId: 'v', item: item, oldTierKey: tk1, newTier: Tier.ice, newTierKey: tk2);
        wipe(item.body); // a delete landing during the rotation re-wrap
        final re = await pending;
        expect(await ItemCrypto.open(vaultId: 'v', tierKey: tk2, item: re), equals(utf8Bytes('hello')),
            reason: 'trial $trial re-wrapped wiped bytes');
      }
    });

    test('open: wiping the item body mid-flight does not change what is opened', () async {
      final tk = randomBytes(32);
      final item = await ItemCrypto.seal(
          vaultId: 'v', tier: Tier.ice, tierKey: tk, itemId: 'i', plaintext: utf8Bytes('hello'));
      final pending = ItemCrypto.open(vaultId: 'v', tierKey: tk, item: item);
      wipe(item.body);
      expect(await pending, equals(utf8Bytes('hello')));
    });
  });
}
