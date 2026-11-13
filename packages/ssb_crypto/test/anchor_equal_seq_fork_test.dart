// SSB-2026-002 follow-up (researcher report, CVSS 7.1): `seq` is per keyring,
// so an EQUAL-seq manifest with different content (two-device fork, or a
// server replaying a sibling write) must not pass the device anchor as fresh.
// The anchor now records seq + the hash of the manifest blob.
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

Future<String> outcome(Future<dynamic> Function() f) async {
  try {
    final r = await f();
    if (r is VaultKeyring) r.dispose();
    return 'OK';
  } on SsbCryptoException catch (e) {
    return 'SSB:${e.message}';
  }
}

void main() {
  final kek = randomBytes(32);

  /// Device A (anchorA) and a forked device B both start from seq 1 and each
  /// write seq 2 with different content.
  Future<(OwnerVault, InMemoryAnchor, StoredVault, StoredVault)> fork() async {
    final anchorA = InMemoryAnchor();
    final a = await OwnerVault.create('v', anchor: anchorA, keks: {'unlock': kek});
    final s1 = await a.write([await a.sealItem(Tier.ice, 'x', 'shared')]);
    // Device B opens the same seq-1 state with its own anchor and writes seq 2.
    final ringB = await s1.open(kek: kek, anchor: InMemoryAnchor());
    final itemB = await ItemCrypto.seal(
        vaultId: 'v', tier: Tier.ice, tierKey: ringB.tierKey(Tier.ice),
        tierEpoch: ringB.tierEpoch(Tier.ice), itemId: 'b', plaintext: bytes('from B'));
    final itemsB = [...s1.items, itemB];
    final tiersB = {for (final t in Tier.values) t: await ringB.wrapTierKey(t)};
    final manifestB = await ringB.sealManifest(items: itemsB);
    expect(ringB.seq, 2);
    final s2b = StoredVault('v', s1.wrappedVaultKeys, s1.slotEpochs, manifestB, tiersB, itemsB);
    // Device A writes its own seq 2.
    final s2a = await a.write([...s1.items, await a.sealItem(Tier.ice, 'a', 'from A')]);
    expect(a.ring.seq, 2);
    ringB.dispose();
    return (a, anchorA, s2a, s2b);
  }

  test('equal seq, different manifest: refused (passphrase and biometric paths)', () async {
    final (a, anchorA, s2a, s2b) = await fork();
    expect(await anchorA.lastSeq('v'), 2);
    expect(await outcome(() => s2b.open(kek: kek, anchor: anchorA)), 'SSB:manifest fork');
    expect(await outcome(() => s2b.openWithVaultKey(vaultKey: a.ring.vaultKey, anchor: anchorA)),
        'SSB:manifest fork');
    // The state this device committed still opens, and the refusals changed nothing.
    expect(await outcome(() => s2a.open(kek: kek, anchor: anchorA)), 'OK');
    expect(await anchorA.lastSeq('v'), 2);
  });

  test('commitManifest records the manifest hash; reopening that blob matches it', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
    final s1 = await o.write([]);
    expect(await anchor.lastHash('v'), isNotNull);
    expect(await outcome(() => s1.open(kek: kek, anchor: anchor)), 'OK');
  });

  test('crash window: write done, commit lost -> next open accepts the newer seq and commits it', () async {
    final anchor = InMemoryAnchor();
    final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
    await o.write([]);
    final s2 = await o.write([await o.sealItem(Tier.ice, 'a', '1')], commit: false);
    expect(await anchor.lastSeq('v'), 1);
    expect(await outcome(() => s2.open(kek: kek, anchor: anchor)), 'OK');
    expect(await anchor.lastSeq('v'), 2);
    expect(await anchor.lastHash('v'), isNotNull);
    expect(await outcome(() => s2.open(kek: kek, anchor: anchor)), 'OK');
  });

  test('seq-only (legacy) anchor: equal seq accepted and upgraded, then a fork at that seq is refused', () async {
    final (_, anchorA, s2a, s2b) = await fork();
    anchorA.dropHash('v'); // anchor as written before the hash existed
    expect(await anchorA.lastHash('v'), isNull);
    expect(await outcome(() => s2a.open(kek: kek, anchor: anchorA)), 'OK');
    expect(await anchorA.lastHash('v'), isNotNull, reason: 'upgraded on the next successful open');
    expect(await outcome(() => s2b.open(kek: kek, anchor: anchorA)), 'SSB:manifest fork');
  });

  test('a newer seq still advances past a recorded hash; older is stale', () async {
    final (a, anchorA, s2a, _) = await fork();
    final s3 = await a.write([...s2a.items]);
    expect(await outcome(() => s3.open(kek: kek, anchor: anchorA)), 'OK');
    expect(await anchorA.lastSeq('v'), 3);
    expect(await outcome(() => s2a.open(kek: kek, anchor: anchorA)), 'SSB:stale manifest');
  });
}
