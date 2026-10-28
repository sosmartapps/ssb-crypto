// SSB-2026-002 Phase 1 (M5): the device anchor refuses an older manifest.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

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
  final kek = randomBytes(32);

  group('seq vs anchor', () {
    test('seq < anchor refused, seq == anchor accepted, seq > anchor accepted and committed', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      final s1 = await o.write([await o.sealItem(Tier.ice, 'a', 'one')]);
      final s2 = await o.write([...s1.items, await o.sealItem(Tier.ice, 'b', 'two')]);
      final s3 = await o.write([...s2.items, await o.sealItem(Tier.ice, 'c', 'three')]);
      expect(o.ring.seq, 3);
      expect(await anchor.lastSeq('v'), 3);

      // The device has seen seq 3.
      expect(await outcome(() => s2.open(kek: kek, anchor: anchor)), 'SSB:stale manifest', reason: 'seq 2 < 3');
      expect(await outcome(() => s1.open(kek: kek, anchor: anchor)), 'SSB:stale manifest', reason: 'seq 1 < 3');
      final r3 = await s3.open(kek: kek, anchor: anchor);
      expect(r3.seq, 3);
      expect(r3.restoredWithoutAnchor, isFalse);
      r3.dispose();

      // A device that stopped at seq 2 accepts 2 (equal) and 3 (newer), then refuses 2.
      final behind = InMemoryAnchor();
      await behind.commit('v', 2);
      final r2 = await s2.open(kek: kek, anchor: behind);
      expect(r2.seq, 2);
      r2.dispose();
      expect(await behind.lastSeq('v'), 2, reason: 'equal seq does not commit');
      final r3b = await s3.open(kek: kek, anchor: behind);
      r3b.dispose();
      expect(await behind.lastSeq('v'), 3, reason: 'newer seq commits');
      expect(await outcome(() => s2.open(kek: kek, anchor: behind)), 'SSB:stale manifest');
      expect(behind.commits, [('v', 2), ('v', 3)]);
    });

    test('the biometric path (fromVaultKey) enforces the same rule', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      final vk = Uint8List.fromList(o.ring.vaultKey);
      final s1 = await o.write([]);
      final s2 = await o.write([await o.sealItem(Tier.secrets, 'x', 'pw')]);
      expect(await outcome(() => s1.openWithVaultKey(vaultKey: vk, anchor: anchor)), 'SSB:stale manifest');
      final r = await s2.openWithVaultKey(vaultKey: vk, anchor: anchor);
      expect(r.seq, 2);
      expect(await o.openItem(s2.items.first), bytes('pw'));
      r.dispose();
    });

    test('a failed check never advances the anchor', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      final s1 = await o.write([await o.sealItem(Tier.ice, 'a', '1')]);
      final s2 = await o.write([...s1.items, await o.sealItem(Tier.ice, 'b', '2')]);
      final fresh = InMemoryAnchor();
      // s2's manifest with s1's items: itemsHash mismatch -> no commit.
      expect(await outcome(() => s2.open(kek: kek, anchor: fresh, items: s1.items)), 'SSB:items do not match manifest');
      expect(await fresh.lastSeq('v'), isNull);
      // s2's manifest with s1's tier wraps (same epochs, different ciphertexts, same keys) -> opens fine
      // (wraps are re-randomised per write; only epochs matter).
      final r = await s2.open(kek: kek, anchor: fresh, tiers: s1.tiers);
      r.dispose();
      expect(await fresh.lastSeq('v'), 2);
    });
  });

  group('missing anchor (new device)', () {
    test('accepted, committed, and reported via restoredWithoutAnchor', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      await o.write([]);
      final s2 = await o.write([await o.sealItem(Tier.ice, 'a', '1')]);
      final newDevice = InMemoryAnchor();
      final r = await s2.open(kek: kek, anchor: newDevice);
      expect(r.restoredWithoutAnchor, isTrue);
      expect(await newDevice.lastSeq('v'), 2);
      r.dispose();
      final again = await s2.open(kek: kek, anchor: newDevice);
      expect(again.restoredWithoutAnchor, isFalse);
      again.dispose();
    });

    test('anchors are per vault id', () async {
      final anchor = InMemoryAnchor();
      final a = await OwnerVault.create('A', anchor: anchor, keks: {'unlock': kek});
      final b = await OwnerVault.create('B', anchor: anchor, keks: {'unlock': kek});
      await a.write([]);
      await a.write([]);
      final sb = await b.write([]);
      expect(await anchor.lastSeq('A'), 2);
      expect(await anchor.lastSeq('B'), 1);
      (await sb.open(kek: kek, anchor: anchor)).dispose();
    });
  });

  group('write-then-commit order (design D7)', () {
    test('sealManifest bumps seq but does not commit; commitManifest does; a lost write leaves the old file openable', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      final s1 = await o.write([]);
      expect(await anchor.lastSeq('v'), 1);
      // Write 2 is sealed but the file write "fails" before commit.
      final s2 = await o.write([await o.sealItem(Tier.ice, 'a', '1')], commit: false);
      expect(o.ring.seq, 2);
      expect(await anchor.lastSeq('v'), 1, reason: 'sealManifest alone must not move the anchor');
      // The device still has file 1 on disk; it must still open.
      (await s1.open(kek: kek, anchor: anchor)).dispose();
      // Now the write succeeds and is committed.
      await o.ring.commitManifest();
      expect(await anchor.lastSeq('v'), 2);
      expect(await outcome(() => s1.open(kek: kek, anchor: anchor)), 'SSB:stale manifest');
      (await s2.open(kek: kek, anchor: anchor)).dispose();
      expect(anchor.commits, [('v', 1), ('v', 2)]);
    });

    test('a crash between write and commit is healed by the next open (seq > anchor commits)', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      await o.write([]);
      final s2 = await o.write([], commit: false); // crashed here
      expect(await anchor.lastSeq('v'), 1);
      final r = await s2.open(kek: kek, anchor: anchor);
      expect(r.seq, 2);
      expect(await anchor.lastSeq('v'), 2);
      r.dispose();
    });

    test('two overlapping sealManifest calls never produce the same seq', () async {
      final o = await OwnerVault.create('v', anchor: InMemoryAnchor(), keks: {'unlock': kek});
      final f1 = o.ring.sealManifest(items: const []);
      final f2 = o.ring.sealManifest(items: const []);
      final m1 = await VaultManifest.open(o.ring.vaultKey, await f1, vaultId: 'v');
      final m2 = await VaultManifest.open(o.ring.vaultKey, await f2, vaultId: 'v');
      expect({m1.seq, m2.seq}, {1, 2});
    });
  });

  group('manifest tampering', () {
    test('wrong vault id, wrong key, replaced manifest, flipped bytes: refused and nothing leaks', () async {
      final anchor = InMemoryAnchor();
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      final s = await o.write([]);
      final other = await OwnerVault.create('v', anchor: InMemoryAnchor(), keks: {'unlock': kek});
      final so = await other.write([]);
      // Another vault's manifest (same id, different Vault Key).
      expect(await outcome(() => s.open(kek: kek, anchor: anchor, manifest: so.manifest)), 'SSB:decrypt failed');
      // Our manifest, their slot wrap (same kek, different Vault Key): the
      // slot opens to THEIR key, under which our manifest does not decrypt.
      expect(await outcome(() => s.open(kek: kek, anchor: anchor, wrappedVaultKey: so.wrappedVaultKeys['unlock'])), 'SSB:decrypt failed');
      // Their whole state under our vault id / anchor: a different vault, not a rollback.
      (await so.open(kek: kek, anchor: InMemoryAnchor())).dispose();
      for (var i = 0; i < s.manifest.length; i += 7) {
        final t = Uint8List.fromList(s.manifest)..[i] ^= 1;
        expect(await outcome(() => s.open(kek: kek, anchor: anchor, manifest: t)), 'SSB:decrypt failed', reason: 'byte $i');
      }
      expect(await outcome(() => s.open(kek: kek, anchor: anchor, vaultId: 'w')), 'SSB:decrypt failed');
    });
  });
}
