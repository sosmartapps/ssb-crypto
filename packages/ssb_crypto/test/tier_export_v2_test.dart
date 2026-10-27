// SSB-2026-002 Phase 1 (M5): tier exports carry epoch, sequence and chain
// hash in their AAD (design D9), so an older export cannot be served as current.
import 'dart:convert';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

void main() {
  group('TierExportCrypto', () {
    final tk = randomBytes(32);
    final pt = bytes('{"items":[]}');

    test('seal / open round trip; header fields match; ObjectType.tierExport', () async {
      final e = await TierExportCrypto.seal(vaultId: 'v', tier: Tier.secrets, tierKey: tk,
          epoch: 3, seq: 7, prevHash: TierExportCrypto.genesisPrevHash, plaintext: pt);
      expect(e.header.epoch, 3);
      expect(e.header.seq, 7);
      expect(e.header.prevHash, Uint8List(32));
      expect(e.ciphertext[5], ObjectType.tierExport.code);
      expect(await TierExportCrypto.open(vaultId: 'v', tier: Tier.secrets, tierKey: tk,
          header: e.header, ciphertext: e.ciphertext), pt);
      // Documented AAD, independently.
      expect(await Aead.open(tk, e.ciphertext, type: ObjectType.tierExport,
          context: ctx2('tier-export', ['v', 'secrets', u32be(3), u32be(7), Uint8List(32)])), pt);
    });

    test('any header field the server edits breaks the open', () async {
      final prev = randomBytes(32);
      final e = await TierExportCrypto.seal(vaultId: 'v', tier: Tier.secrets, tierKey: tk,
          epoch: 3, seq: 7, prevHash: prev, plaintext: pt);
      Future<Uint8List> open(TierExportHeader h, {String vaultId = 'v', Tier tier = Tier.secrets}) =>
          TierExportCrypto.open(vaultId: vaultId, tier: tier, tierKey: tk, header: h, ciphertext: e.ciphertext);
      await expectLater(open(TierExportHeader(epoch: 2, seq: 7, prevHash: prev)), throwsSsb);
      await expectLater(open(TierExportHeader(epoch: 4, seq: 7, prevHash: prev)), throwsSsb);
      await expectLater(open(TierExportHeader(epoch: 3, seq: 6, prevHash: prev)), throwsSsb);
      await expectLater(open(TierExportHeader(epoch: 3, seq: 8, prevHash: prev)), throwsSsb);
      await expectLater(open(TierExportHeader(epoch: 3, seq: 7, prevHash: Uint8List.fromList(prev)..[31] ^= 1)), throwsSsb);
      await expectLater(open(e.header, vaultId: 'w'), throwsSsb);
      await expectLater(open(e.header, tier: Tier.essentials), throwsSsb);
      await expectLater(Aead.open(tk, e.ciphertext, type: ObjectType.item,
          context: TierExportCrypto.context('v', Tier.secrets, 3, 7, prev)), throwsSsb);
      expect(await open(e.header), pt);
    });

    test('header JSON round trip and strictness', () {
      final h = TierExportHeader(epoch: 1, seq: 2, prevHash: randomBytes(32));
      final j = h.toJson();
      expect(j['v'], 2);
      expect((j['prevHash'] as String).length, 64);
      final back = TierExportHeader.fromJson(jsonDecode(jsonEncode(j)) as Map<String, dynamic>);
      expect(back.epoch, 1);
      expect(back.seq, 2);
      expect(back.prevHash, h.prevHash);
      expect(() => TierExportHeader.fromJson({...j, 'v': 1}), throwsSsb);
      expect(() => TierExportHeader.fromJson({...j, 'epoch': '1'}), throwsSsb);
      expect(() => TierExportHeader.fromJson({...j, 'prevHash': 'zz' * 32}), throwsSsb);
      expect(() => TierExportHeader.fromJson({...j, 'prevHash': 'ab' * 31}), throwsSsb);
      expect(() => TierExportHeader.fromJson({...j}..remove('seq')), throwsSsb);
      expect(() => TierExportHeader(epoch: -1, seq: 0, prevHash: Uint8List(32)), throwsSsb);
      expect(() => TierExportHeader(epoch: 0, seq: 0x100000000, prevHash: Uint8List(32)), throwsSsb);
      expect(() => TierExportHeader(epoch: 0, seq: 0, prevHash: Uint8List(31)), throwsSsb);
    });
  });

  group('VaultKeyring.sealTierExport chain', () {
    test('seq increments, prevHash chains, head lands in the manifest, epoch follows rotation', () async {
      final anchor = InMemoryAnchor();
      final kek = randomBytes(32);
      final o = await OwnerVault.create('v', anchor: anchor, keks: {'unlock': kek});
      expect(o.ring.tierExportSeq(Tier.secrets), 0);
      expect(o.ring.tierExportHead(Tier.secrets), isNull);

      final e1 = await o.ring.sealTierExport(Tier.secrets, bytes('one'));
      expect(e1.header.seq, 1);
      expect(e1.header.epoch, 1);
      expect(e1.header.prevHash, TierExportCrypto.genesisPrevHash);
      expect(o.ring.tierExportSeq(Tier.secrets), 1);
      expect(o.ring.tierExportHead(Tier.secrets), hexEncode(TierExportCrypto.hash(e1.ciphertext)));

      final e2 = await o.ring.sealTierExport(Tier.secrets, bytes('two'));
      expect(e2.header.seq, 2);
      expect(e2.header.prevHash, TierExportCrypto.hash(e1.ciphertext));

      // Other tiers have their own chains.
      final f1 = await o.ring.sealTierExport(Tier.essentials, bytes('e'));
      expect(f1.header.seq, 1);
      expect(f1.header.prevHash, TierExportCrypto.genesisPrevHash);

      // Rotation bumps the epoch of later exports; the sequence keeps counting.
      o.ring.rotateTier(Tier.secrets);
      final e3 = await o.ring.sealTierExport(Tier.secrets, bytes('three'));
      expect(e3.header.epoch, 2);
      expect(e3.header.seq, 3);
      expect(e3.header.prevHash, TierExportCrypto.hash(e2.ciphertext));

      final s = await o.write([]);
      final m = await VaultManifest.open(o.ring.vaultKey, s.manifest, vaultId: 'v');
      expect(m.tierExportSeq, {Tier.secrets: 3, Tier.essentials: 1});
      expect(m.tierExportHead[Tier.secrets], hexEncode(TierExportCrypto.hash(e3.ciphertext)));
      expect(m.tierExportHead[Tier.essentials], hexEncode(TierExportCrypto.hash(f1.ciphertext)));

      // A reopened keyring continues the chain where the manifest says.
      final r = await s.open(kek: kek, anchor: anchor);
      expect(r.tierExportSeq(Tier.secrets), 3);
      final e4 = await r.sealTierExport(Tier.secrets, bytes('four'));
      expect(e4.header.seq, 4);
      expect(e4.header.prevHash, TierExportCrypto.hash(e3.ciphertext));
      expect(e4.header.epoch, 2);
      r.dispose();
    });

    test('a beneficiary with the right tier key opens only the export whose header it was given; older epochs fail', () async {
      final o = await OwnerVault.create('v', anchor: InMemoryAnchor());
      final oldKey = Uint8List.fromList(o.ring.tierKey(Tier.secrets));
      final e1 = await o.ring.sealTierExport(Tier.secrets, bytes('gen1'));
      o.ring.rotateTier(Tier.secrets);
      final newKey = o.ring.tierKey(Tier.secrets);
      final e2 = await o.ring.sealTierExport(Tier.secrets, bytes('gen2'));
      // Current kit (epoch 2 key) vs the server replaying the epoch-1 export: fails.
      await expectLater(TierExportCrypto.open(vaultId: 'v', tier: Tier.secrets, tierKey: newKey,
          header: e1.header, ciphertext: e1.ciphertext), throwsSsb);
      // The old key still opens the old export -- ciphertext cannot be
      // unsent (F1, inherent); the HEADER now says it is epoch 1, which the
      // recovery tool compares to the kit's epoch (design D11).
      expect(await TierExportCrypto.open(vaultId: 'v', tier: Tier.secrets, tierKey: oldKey,
          header: e1.header, ciphertext: e1.ciphertext), bytes('gen1'));
      expect(e1.header.epoch, 1);
      expect(e2.header.epoch, 2);
      expect(await TierExportCrypto.open(vaultId: 'v', tier: Tier.secrets, tierKey: newKey,
          header: e2.header, ciphertext: e2.ciphertext), bytes('gen2'));
    });
  });
}
