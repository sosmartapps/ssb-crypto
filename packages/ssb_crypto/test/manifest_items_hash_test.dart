// SSB-2026-002 Phase 1 (M3): VaultManifest canonical encoding, sealing and
// the item-set / beneficiary-set hashes.
import 'dart:convert';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());
Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));

VaultManifest sample({int seq = 3, String itemsHash = ''}) => VaultManifest(
      vaultId: 'vault-1',
      seq: seq,
      tierEpochs: {Tier.secrets: 2, Tier.ice: 1, Tier.essentials: 1},
      slotEpochs: {'unlock': 1, 'recovery': 0},
      slotHashes: {'unlock': 'a' * 64, 'recovery': 'b' * 64},
      tierExportSeq: {Tier.secrets: 9},
      tierExportHead: {Tier.secrets: 'c' * 64},
      itemsHash: itemsHash.isEmpty ? VaultManifest.itemsHashHex(const []) : itemsHash,
      beneficiarySetHash: VaultManifest.beneficiarySetHashHex(const []),
    );

void main() {
  group('canonical JSON', () {
    test('keys sorted at every level, no whitespace, independent of construction order', () {
      final m = sample();
      final s = utf8.decode(m.encode());
      expect(s, startsWith('{"beneficiarySetHash":"'));
      expect(s, contains('"tierEpochs":{"essentials":1,"ice":1,"secrets":2}'));
      expect(s, contains('"slotEpochs":{"recovery":0,"unlock":1}'));
      expect(s, contains('"v":2'));
      expect(s, isNot(contains(' ')));
      expect(s, isNot(contains('\n')));
      // Same content, different map insertion order -> identical bytes.
      final m2 = VaultManifest(
        vaultId: 'vault-1', seq: 3,
        tierEpochs: {Tier.ice: 1, Tier.essentials: 1, Tier.secrets: 2},
        slotEpochs: {'recovery': 0, 'unlock': 1},
        slotHashes: {'recovery': 'b' * 64, 'unlock': 'a' * 64},
        tierExportSeq: {Tier.secrets: 9}, tierExportHead: {Tier.secrets: 'c' * 64},
        itemsHash: m.itemsHash, beneficiarySetHash: m.beneficiarySetHash,
      );
      expect(m2.encode(), m.encode());
      expect(VaultManifest.canonicalJson({'b': {'z': 1, 'a': [3, {'y': 1, 'x': 2}]}, 'a': 0}),
          '{"a":0,"b":{"a":[3,{"x":2,"y":1}],"z":1}}');
    });

    test('decode round trip; strict on type, range, unknown keys, missing tier, version', () {
      final m = sample();
      final back = VaultManifest.decode(m.encode());
      expect(back.encode(), m.encode());
      expect(back.tierEpochs[Tier.secrets], 2);
      expect(back.slotEpochs['recovery'], 0);
      expect(back.tierExportSeq[Tier.secrets], 9);
      expect(back.tierExportHead[Tier.essentials], isNull);

      Map<String, dynamic> j() => jsonDecode(utf8.decode(m.encode())) as Map<String, dynamic>;
      void bad(void Function(Map<String, dynamic>) mut, String why) {
        final x = j();
        mut(x);
        expect(() => VaultManifest.fromJson(x), throwsSsb, reason: why);
      }
      bad((x) => x['v'] = 1, 'v1');
      bad((x) => x['v'] = '2', 'v as string');
      bad((x) => x.remove('seq'), 'missing seq');
      bad((x) => x['extra'] = 1, 'unknown key');
      bad((x) => x['seq'] = -1, 'negative seq');
      bad((x) => x['seq'] = 0x100000000, 'seq > u32');
      bad((x) => x['seq'] = 1.5, 'seq double');
      bad((x) => (x['tierEpochs'] as Map).remove('ice'), 'missing tier');
      bad((x) => (x['tierEpochs'] as Map)['bogus'] = 1, 'unknown tier');
      bad((x) => (x['tierEpochs'] as Map)['ice'] = '1', 'epoch string');
      bad((x) => (x['slotHashes'] as Map)['unlock'] = 'A' * 64, 'uppercase hex');
      bad((x) => (x['slotHashes'] as Map)['unlock'] = 'a' * 63, 'short hex');
      bad((x) => x['itemsHash'] = 'zz' * 32, 'non-hex');
      bad((x) => (x['tierExportSeq'] as Map)['secrets'] = -2, 'negative export seq');
      bad((x) => x['vaultId'] = 7, 'vaultId int');
      expect(() => VaultManifest.decode(b('not json')), throwsSsb);
      expect(() => VaultManifest.decode(b('[1,2]')), throwsSsb);
      expect(() => VaultManifest.decode(Uint8List.fromList([0xff, 0xfe])), throwsSsb);
    });
  });

  group('seal / open', () {
    final vk = randomBytes(32);
    test('round trip under the vault key with ObjectType.manifest and ctx2(manifest, vaultId)', () async {
      final m = sample();
      final blob = await VaultManifest.seal(vk, m);
      expect(blob[5], ObjectType.manifest.code);
      final back = await VaultManifest.open(vk, blob, vaultId: 'vault-1');
      expect(back.encode(), m.encode());
      // Independently with Aead and the documented context.
      final pt = await Aead.open(vk, blob, type: ObjectType.manifest, context: ctx2('manifest', ['vault-1']));
      expect(pt, m.encode());
    });

    test('wrong vault id, wrong key, wrong type, any byte flip: refused', () async {
      final blob = await VaultManifest.seal(vk, sample());
      await expectLater(VaultManifest.open(vk, blob, vaultId: 'vault-2'), throwsSsb);
      await expectLater(VaultManifest.open(randomBytes(32), blob, vaultId: 'vault-1'), throwsSsb);
      await expectLater(Aead.open(vk, blob, type: ObjectType.item, context: ctx2('manifest', ['vault-1'])), throwsSsb);
      for (var i = 0; i < blob.length; i += 5) {
        final t = Uint8List.fromList(blob)..[i] ^= 0x10;
        await expectLater(VaultManifest.open(vk, t, vaultId: 'vault-1'), throwsSsb, reason: 'byte $i');
      }
    });

    test('a manifest whose body names another vault is refused even if sealed under the right context', () async {
      // Sealed by hand with vault-1's context but claiming vault-2 inside.
      final other = VaultManifest(
        vaultId: 'vault-2', seq: 1,
        tierEpochs: {for (final t in Tier.values) t: 1}, slotEpochs: const {}, slotHashes: const {},
        tierExportSeq: const {}, tierExportHead: const {},
        itemsHash: VaultManifest.itemsHashHex(const []), beneficiarySetHash: VaultManifest.beneficiarySetHashHex(const []),
      );
      final blob = await Aead.seal(vk, other.encode(), type: ObjectType.manifest, context: ctx2('manifest', ['vault-1']));
      await expectLater(VaultManifest.open(vk, blob, vaultId: 'vault-1'), throwsSsb);
    });
  });

  group('itemsHash', () {
    final tk = randomBytes(32);
    Future<SealedItem> item(String id, Tier t, String body) =>
        ItemCrypto.seal(vaultId: 'v', tier: t, tierKey: tk, tierEpoch: 1, itemId: id, plaintext: b(body));

    test('order-independent, 32 bytes, empty set is a fixed value', () async {
      final a = await item('a', Tier.ice, 'x'), c = await item('c', Tier.secrets, 'y');
      final h1 = VaultManifest.computeItemsHash([a, c]), h2 = VaultManifest.computeItemsHash([c, a]);
      expect(h1, h2);
      expect(h1.length, 32);
      expect(VaultManifest.computeItemsHash(const []), VaultManifest.computeItemsHash(const []));
      expect(VaultManifest.itemsHashHex(const []),
          hexEncode(sha256Of(concatBytes([utf8Bytes('ssb/v2/items-hash'), u32be(0)]))));
    });

    test('changes when an item is added, removed, re-sealed (F2a), re-tiered or re-wrapped (F2b)', () async {
      final a = await item('a', Tier.ice, 'x'), c = await item('c', Tier.secrets, 'y');
      final base = VaultManifest.computeItemsHash([a, c]);
      expect(VaultManifest.computeItemsHash([a]), isNot(base), reason: 'removed');
      expect(VaultManifest.computeItemsHash([a, c, await item('d', Tier.ice, 'z')]), isNot(base), reason: 'added');
      final aEdited = await item('a', Tier.ice, 'x2'); // fresh item key per seal
      expect(VaultManifest.computeItemsHash([aEdited, c]), isNot(base), reason: 're-sealed');
      final aMoved = SealedItem('a', Tier.secrets, a.wrappedItemKey, a.body);
      expect(VaultManifest.computeItemsHash([aMoved, c]), isNot(base), reason: 're-tiered');
      final tk2 = randomBytes(32);
      final aRewrapped = await ItemCrypto.rewrapItemKey(vaultId: 'v', item: a, oldTierKey: tk, oldTierEpoch: 1,
          newTier: Tier.ice, newTierKey: tk2, newTierEpoch: 2);
      expect(VaultManifest.computeItemsHash([aRewrapped, c]), isNot(base), reason: 're-wrapped');
      // The body is not part of the hash input (bound via the item key instead).
      final aBodySwapped = SealedItem('a', Tier.ice, a.wrappedItemKey, randomBytes(a.body.length));
      expect(VaultManifest.computeItemsHash([aBodySwapped, c]), base);
    });

    test('field boundaries are unambiguous (length prefixes)', () async {
      final k = randomBytes(70);
      final x = SealedItem('ab', Tier.ice, k, Uint8List(0));
      final y = SealedItem('a', Tier.ice, k, Uint8List(0));
      expect(VaultManifest.computeItemsHash([x]), isNot(VaultManifest.computeItemsHash([y])));
      final p = SealedItem('a', Tier.ice, Uint8List.fromList([1, ...k]), Uint8List(0));
      final q = SealedItem('a', Tier.ice, k, Uint8List.fromList([1]));
      expect(VaultManifest.computeItemsHash([p]), isNot(VaultManifest.computeItemsHash([q])));
    });
  });

  group('beneficiarySetHash', () {
    test('order-independent, duplicates collapse, sensitive to membership', () {
      final h = VaultManifest.computeBeneficiarySetHash(['b1', 'b2']);
      expect(VaultManifest.computeBeneficiarySetHash(['b2', 'b1']), h);
      expect(VaultManifest.computeBeneficiarySetHash(['b2', 'b1', 'b1']), h);
      expect(VaultManifest.computeBeneficiarySetHash(['b1']), isNot(h));
      expect(VaultManifest.computeBeneficiarySetHash(['b1', 'b2', 'b3']), isNot(h));
      expect(VaultManifest.computeBeneficiarySetHash(['b1b', '2']), isNot(h));
      expect(VaultManifest.computeBeneficiarySetHash(const []).length, 32);
    });
  });
}
