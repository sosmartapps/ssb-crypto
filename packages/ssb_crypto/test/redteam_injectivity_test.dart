// Red team 2026-10-26 (SSB-2026-004 follow-up): every context / AAD / info /
// label builder in ssb_crypto is fed delimiter-laden ids and must be
// INJECTIVE -- distinct argument tuples give distinct bytes -- and builders
// for different purposes must never produce the same bytes (domain
// separation). SSB-2026-004 was one unprefixed builder; this file is the
// whole class, so the next one is caught by a test instead of a researcher.
//
// Also: a label registry. Any new 'ssb/vN/...' literal or ctx2('what') in
// lib/ fails the scan below until it is registered here, which is the prompt
// to add the new builder to the injectivity table.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/legacy_v1.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'v2_util.dart';

/// Strings that have broken (or would break) '|'-delimited concatenation.
final _gcm = AesGcm.with256bits();
SecretKey _sk(Uint8List k) => SecretKeyData(k);

final List<String> adv = [
  '',
  '|',
  'vault:',
  'tier:ice',
  'item:',
  '|tier:ice|item:',
  'V',
  'V|tier:ice|item:B',
  'B',
  'B|tier:ice|item:C',
  'C',
  'a\u0000b',
  'é', // e-acute, precomposed
  'é', // e + combining acute (NFD of the above)
  '\u{1F600}',
  'ik',
  'vk',
  'x' * 5000,
];

String _id(List<int> b) => hexEncode(sha256Of(b));

/// Collects (tuple label, bytes) rows and fails on the first two different
/// tuples with identical bytes.
class Rows {
  final Map<String, String> _seen = {}; // bytes-hash -> tuple label
  int count = 0;

  void add(String tuple, List<int> bytes) {
    count++;
    final h = _id(bytes);
    final prev = _seen[h];
    if (prev != null && prev != tuple) {
      fail('COLLISION: "$prev" and "$tuple" produce identical bytes');
    }
    _seen[h] = tuple;
  }
}

String _show(String s) => s.length > 20 ? '<${s.length} chars>' : jsonEncode(s);

void main() {
  group('ctx2 and every in-tree user is injective and domain separated', () {
    test('ctx2: (what, fields) tuples never collide, any field count', () {
      final r = Rows();
      for (final w in adv) {
        r.add('ctx2(${_show(w)},[])', ctx2(w, []));
        for (final a in adv) {
          r.add('ctx2(${_show(w)},[${_show(a)}])', ctx2(w, [a]));
          for (final b in adv) {
            r.add('ctx2(${_show(w)},[${_show(a)},${_show(b)}])', ctx2(w, [a, b]));
          }
        }
      }
      expect(r.count, greaterThan(5000));
    });

    test('ctx2 raw byte fields: fixed width is the caller contract (documented trap)', () {
      // A variable-width raw field is NOT injective. This is why ctx2 refuses
      // bare ints and why every in-tree raw field is u32be / a 32-byte hash
      // (scan below). If this ever starts passing as "distinct", ctx2 changed.
      final a = ctx2('t', [Uint8List.fromList([1, 2]), Uint8List.fromList([3])]);
      final b = ctx2('t', [Uint8List.fromList([1]), Uint8List.fromList([2, 3])]);
      expect(a, equals(b), reason: 'variable-width raw fields are ambiguous by design');
      // ...and bare ints are refused so the width is always explicit.
      expect(() => ctx2('t', [7]), throwsArgumentError);
    });

    test('all v2 builders together: nothing collides within or across builders', () {
      final r = Rows();
      const epochs = [0, 1, 2, 65535, 0xffffffff];
      for (final v in adv) {
        r.add('manifest(${_show(v)})', VaultManifest.context(v));
        for (final x in adv) {
          for (final e in epochs) {
            r.add('vk(${_show(v)},${_show(x)},$e)', VaultKeyring.vkContext(v, x, e));
          }
          r.add('item(${_show(v)},${_show(x)})', ItemCrypto.bodyContext(v, x));
          r.add('file(${_show(v)},${_show(x)})', ItemCrypto.fileContext(v, x));
          for (final t in Tier.values) {
            for (final e in epochs) {
              r.add('ik(${_show(v)},${t.name},$e,${_show(x)})',
                  ItemCrypto.keyContext(v, t, e, x));
            }
          }
        }
        for (final t in Tier.values) {
          for (final e in epochs) {
            r.add('tk(${_show(v)},${t.name},$e)', VaultKeyring.tkContext(v, t, e));
            for (final s in const [0, 1, 7, 0xffffffff]) {
              for (final ph in [Uint8List(32), Uint8List(32)..fillRange(0, 32, 1)]) {
                r.add('tier-export(${_show(v)},${t.name},$e,$s,${ph[0]})',
                    TierExportCrypto.context(v, t, e, s, ph));
              }
            }
          }
        }
      }
      expect(r.count, greaterThan(9000));
    });

    test('a v2 context is never equal to the v1 context of the same ids', () {
      for (final v in adv) {
        for (final x in adv) {
          for (final t in Tier.values) {
            expect(ItemCrypto.keyContext(v, t, 1, x),
                isNot(equals(ItemCryptoV1.keyContext(v, t, x))));
          }
          expect(ItemCrypto.bodyContext(v, x), isNot(equals(ItemCryptoV1.bodyContext(v, x))));
        }
      }
    });
  });

  group('S2 HPKE info (Release.s2Info)', () {
    test('injective over vault id, beneficiary id, tier, epoch', () {
      final r = Rows();
      for (final v in adv) {
        for (final b in adv) {
          for (final t in Tier.values) {
            for (final e in const [0, 1, 255, 256, 65535]) {
              r.add('s2(${_show(v)},${_show(b)},${t.name},$e)',
                  Release.s2Info(v, b, t, epoch: e));
            }
          }
        }
      }
      expect(r.count, greaterThan(3000));
    });

    test('v1 S2 info is a strict prefix of the v2 one, never equal (documented)', () {
      final v1 = ReleaseV1.s2Info('V', 'B', Tier.secrets);
      final v2 = Release.s2Info('V', 'B', Tier.secrets, epoch: 1);
      expect(v2.length, v1.length + 2);
      expect(v2.sublist(0, v1.length), equals(v1));
      expect(v2, isNot(equals(v1)));
    });
  });

  group('owner challenge message and signature domains', () {
    test('auth and delete purposes are prefix-free (the message starts with the raw purpose)', () {
      final a = utf8Bytes(OwnerIdentity.authPurpose), d = utf8Bytes(OwnerIdentity.deletePurpose);
      bool isPrefix(List<int> p, List<int> s) =>
          p.length <= s.length && List.generate(p.length, (i) => p[i] == s[i]).every((x) => x);
      expect(isPrefix(a, d), isFalse);
      expect(isPrefix(d, a), isFalse);
    });

    test('challengeMessage is injective over (purpose, vaultId, nonce)', () {
      final r = Rows();
      final nonces = <String, Uint8List>{
        'zeros16': Uint8List(16),
        'ones16': Uint8List(16)..fillRange(0, 16, 1),
        'zeros17': Uint8List(17),
        'zeros64': Uint8List(64),
        'lp-lookalike': Uint8List.fromList([...lengthPrefixed('V'), ...Uint8List(12)]),
      };
      for (final p in const [OwnerIdentity.authPurpose, OwnerIdentity.deletePurpose]) {
        for (final v in adv) {
          for (final n in nonces.entries) {
            r.add('chal($p,${_show(v)},${n.key})',
                OwnerIdentity.challengeMessage(v, n.value, purpose: p));
          }
        }
      }
      expect(r.count, greaterThan(150));
    });

    test('HybridSignature domain: (purpose, message) pairs that concatenate alike do not verify across', () async {
      final kp = await HybridSignature.generateKeyPair();
      final sig = await HybridSignature.sign(kp.secretKey, bytes('bc'), purpose: 'a');
      expect(await HybridSignature.verify(kp.publicKey, bytes('bc'), sig, purpose: 'a'), isTrue);
      // purpose 'ab' + message 'c' and purpose 'a' + message 'bc' concatenate alike.
      expect(await HybridSignature.verify(kp.publicKey, bytes('c'), sig, purpose: 'ab'), isFalse);
      // A purpose that embeds the length prefix and the message.
      final p = String.fromCharCodes([0, 1, 0x61]); // looks like u16(1) 'a'
      expect(await HybridSignature.verify(kp.publicKey, bytes('bc'), sig, purpose: p), isFalse);
      wipe(kp.secretKey);
    });
  });

  group('set hashes (manifest)', () {
    final keyA = Uint8List.fromList(List.generate(61, (i) => i));
    final keyB = Uint8List.fromList(List.generate(61, (i) => 200 - i));
    SealedItem item(String id, Tier t, Uint8List k) => SealedItem(id, t, k, Uint8List(0));

    test('itemsHash: distinct item sets with delimiter-laden ids hash differently', () {
      final r = Rows();
      final ids = [...adv, 'a\u0000ice', 'a\u0000ice\u0000${hexEncode(keyA)}'];
      for (final i in ids) {
        for (final t in Tier.values) {
          for (final k in [keyA, keyB]) {
            r.add('1:${_show(i)}|${t.name}|${k[0]}', VaultManifest.computeItemsHash([item(i, t, k)]));
          }
        }
      }
      // pairs: (x,y) vs the single item whose id is the concatenation
      for (final x in ['a', 'a\u0000ice\u0000', '']) {
        for (final y in ['b', '\u0000ice\u0000b', '']) {
          r.add('2:${_show(x)}+${_show(y)}',
              VaultManifest.computeItemsHash([item(x, Tier.ice, keyA), item(y, Tier.ice, keyB)]));
        }
      }
      expect(r.count, greaterThan(100));
    });

    test('itemsHash: order independent, and a duplicated item is not the same set', () {
      final x = item('a', Tier.ice, keyA), y = item('b', Tier.secrets, keyB);
      expect(VaultManifest.computeItemsHash([x, y]), VaultManifest.computeItemsHash([y, x]));
      expect(VaultManifest.computeItemsHash([x, x]), isNot(VaultManifest.computeItemsHash([x])));
      expect(VaultManifest.computeItemsHash([]), isNot(VaultManifest.computeItemsHash([x])));
    });

    test('beneficiary set hash: entries are not re-splittable', () {
      final sets = <List<String>>[
        [],
        [''],
        ['', ''], // dedupes to ['']
        ['a', 'b'],
        ['ab'],
        ['a|b'],
        ['a', 'b', 'c'],
        ['a,b', 'c'],
        ['abc'],
        ['\u0000'],
      ];
      final r = Rows();
      for (final s in sets) {
        // ['', ''] collapses to [''] by design (duplicates collapsed): same tuple label.
        final canon = (s.toSet().toList()..sort()).map(jsonEncode).join(',');
        r.add('set[$canon]', VaultManifest.computeBeneficiarySetHash(s));
      }
      expect(VaultManifest.computeBeneficiarySetHash(['b', 'a']),
          VaultManifest.computeBeneficiarySetHash(['a', 'b']));
    });
  });

  group('kit codes and share check', () {
    test('production labels: no code for one purpose decodes as another', () async {
      final specs = <(String, int)>[
        (Unlock.secretKeyLabel, Unlock.secretKeyLength),
        (VaultKeyring.recoveryKeyLabel, 32),
        (Release.s1Label, 61),
        (Release.s3Label, 61),
      ];
      for (final a in specs) {
        final code = await KitCode.encode(a.$1, randomBytes(a.$2));
        for (final b in specs) {
          final dec = KitCode.decode(b.$1, code, payloadLength: b.$2);
          if (a.$1 == b.$1) {
            expect((await dec).length, a.$2);
          } else {
            await expectLater(dec, throwsA(isA<SsbCryptoException>()),
                reason: '${a.$1} code accepted as ${b.$1}');
          }
        }
      }
    });

    test('labels are prefix-free (decode strips the label with startsWith)', () {
      final labels = [Unlock.secretKeyLabel, VaultKeyring.recoveryKeyLabel, Release.s1Label, Release.s3Label]
          .map((l) => l.toUpperCase().replaceAll('-', ''))
          .toList();
      for (final a in labels) {
        for (final b in labels) {
          if (a != b) expect(b.startsWith(a), isFalse, reason: '$a is a prefix of $b');
        }
      }
    });

    test('KitCode checksum ("ssb/v1/kit|LABEL|" + payload) is ambiguous for labels containing "|" (documented)', () async {
      // checksum(label 'LA', payload 'B|'+P) == checksum(label 'LA|B', payload P):
      // both hash 'ssb/v1/kit|LA|B|' + P. Unreachable: labels are four
      // compile-time constants without '|', and the checksum is a 4-byte
      // typo guard, not authentication.
      final p = bytes('PAYLOAD!');
      final c1 = await KitCode.encode('LA', Uint8List.fromList([...utf8.encode('B|'), ...p]));
      final c2 = await KitCode.encode('LA|B', p);
      List<int> tail(String code, int payloadLen) {
        final body = code.substring(code.indexOf('-') + 1).replaceAll('-', '');
        const alpha = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
        final out = <int>[];
        var buf = 0, bits = 0;
        for (final ch in body.split('')) {
          buf = (buf << 5) | alpha.indexOf(ch);
          bits += 5;
          if (bits >= 8) {
            out.add((buf >> (bits - 8)) & 0xff);
            bits -= 8;
            buf &= (1 << bits) - 1;
          }
        }
        expect(out.length, payloadLen + 4);
        return out.sublist(payloadLen);
      }

      expect(tail(c1, 10), equals(tail(c2, 8)),
          reason: 'if this fails the checksum became label-length-prefixed: delete this documentation test');
    });

    test('Shamir keyCheck is bound to the epoch and the split salt', () async {
      final secret = randomBytes(32);
      final s1 = await Shamir.split(secret, epoch: 1);
      final s2 = await Shamir.split(secret, epoch: 2);
      final s1b = await Shamir.split(secret, epoch: 1);
      expect(s1[0].keyCheck, isNot(equals(s2[0].keyCheck)));
      expect(s1[0].keyCheck, isNot(equals(s1b[0].keyCheck)), reason: 'salted: independent splits differ');
      // Rewriting the epoch on every share (what a server serving an old kit
      // as a new generation would do) breaks the reconstruction check.
      final forged = [
        for (final s in s1.take(2)) Share(s.threshold, s.x, 2, s.salt, s.keyCheck, s.y)
      ];
      await expectLater(Shamir.combine(forged), throwsA(isA<SsbCryptoException>()));
      expect(await Shamir.combine(s1.take(2).toList()), secret);
    });
  });

  group('legacy v1 builders (open-only): collisions DOCUMENTED, reachability bounded', () {
    // The reporter's tuples (SSB-2026-004).
    const aV = 'V|tier:ice|item:B', aI = 'C';
    const bV = 'V', bI = 'B|tier:ice|item:C';

    test('the v1 item-key context STILL collides for the reporter tuples (kept for migration)', () {
      expect(ItemCryptoV1.keyContext(aV, Tier.ice, aI), equals(ItemCryptoV1.keyContext(bV, Tier.ice, bI)));
    });

    test('...but the v1 body context does not, so no item plaintext crosses over', () {
      expect(ItemCryptoV1.bodyContext(aV, aI), isNot(equals(ItemCryptoV1.bodyContext(bV, bI))));
    });

    test('v1 collisions across tiers: (V|tier:T1|item:X, T2, Y) vs (V, T1, X|tier:T2|item:Y)', () {
      for (final t1 in Tier.values) {
        for (final t2 in Tier.values) {
          final a = ItemCryptoV1.keyContext('V|tier:${t1.name}|item:X', t2, 'Y');
          final b = ItemCryptoV1.keyContext('V', t1, 'X|tier:${t2.name}|item:Y');
          expect(a, equals(b), reason: '${t1.name}/${t2.name}');
        }
      }
    });

    test('legacyVkContext collides for (slot, vault) splits across "|vault:" (documented)', () {
      expect(VaultKeyring.legacyVkContext('c', 'a|vault:b'),
          equals(VaultKeyring.legacyVkContext('b|vault:c', 'a')));
    });

    test('REACHABILITY: within ONE vault id the v1 item/file key and tier-export contexts are injective', () {
      // The tier key that opens a wrap belongs to one vault, and the callers
      // (vault_migration.dart, claim_recovery.dart) pass that vault's id. So
      // what matters is injectivity for a fixed vault id over everything an
      // attacker can vary: the item id (stored/served) and the tier. It holds.
      for (final v in adv) {
        final r = Rows();
        for (final t in Tier.values) {
          for (final i in adv) {
            r.add('ik(${t.name},${_show(i)})', ItemCryptoV1.keyContext(v, t, i));
          }
          r.add('te(${t.name})', TierExportV1.context(v, t));
          r.add('tk(${t.name})', VaultKeyringV1.tkContext(v, t));
        }
        for (final i in adv) {
          r.add('body(${_show(i)})', ItemCryptoV1.bodyContext(v, i));
        }
        // different builders never alias each other either
        expect(r.count, greaterThan(50));
      }
    });

    test('REACHABILITY: ids the app generates (hex / v2_ / b_ / fixed names / uuid) never collide in v1', () {
      final vaultIds = [
        hexEncode(List.generate(16, (i) => i)),
        hexEncode(List.generate(16, (i) => 255 - i)),
        'v2_${hexEncode(List.generate(20, (i) => i))}',
        'v2_${hexEncode(List.generate(20, (i) => 100 + i))}',
        'v1-vault',
      ];
      final itemIds = [
        'beneficiaries.v1',
        'readiness.v1',
        'b_lx3k9_a1b2c3',
        'b_lx3k9_a1b2c4',
        '123e4567-e89b-12d3-a456-426614174000',
        'i1',
        'i2',
      ];
      final r = Rows();
      for (final v in vaultIds) {
        for (final t in Tier.values) {
          for (final i in itemIds) {
            r.add('ik($v,${t.name},$i)', ItemCryptoV1.keyContext(v, t, i));
            r.add('body($v,$i)', ItemCryptoV1.bodyContext(v, i));
          }
          r.add('te($v,${t.name})', TierExportV1.context(v, t));
        }
        for (final slot in const ['unlock', 'recovery']) {
          r.add('vk($v,$slot)', VaultKeyring.legacyVkContext(v, slot));
        }
      }
      expect(r.count, greaterThan(100));
    });

    test('END TO END: a v1 key wrap sealed under tuple A unwraps at the wrap layer under B, but ItemCryptoV1.open still fails', () async {
      final tk = randomBytes(32), ik = randomBytes(32);
      Future<Uint8List> sealV1(Uint8List key, Uint8List pt, ObjectType type, List<int> ctx) async {
        // v1 Aead.seal: header(v1) | nonce | ct | tag, AAD = header || ctx
        final h = buildHeader(type, formatVersion: 1);
        final n = randomBytes(12);
        final box = await _gcm.encrypt(pt, secretKey: _sk(key), nonce: n, aad: [...h, ...ctx]);
        return concatBytes([h, n, box.cipherText, box.mac.bytes]);
      }

      final padded = Uint8List(256)..setAll(4, bytes('secret'))..setAll(0, u32be(6));
      final wrapped = await sealV1(tk, ik, ObjectType.wrappedKey, ItemCryptoV1.keyContext(aV, Tier.ice, aI));
      final body = await sealV1(ik, padded, ObjectType.item, ItemCryptoV1.bodyContext(aV, aI));
      // wrap layer under tuple B: opens (the collision)
      final unwrapped = await Aead.openLegacyV1(tk, wrapped,
          type: ObjectType.wrappedKey, context: ItemCryptoV1.keyContext(bV, Tier.ice, bI));
      expect(unwrapped, ik);
      // the real open path under tuple B: body AAD differs -> fails closed
      await expectLater(
          ItemCryptoV1.open(vaultId: bV, tierKey: tk, item: SealedItem(bI, Tier.ice, wrapped, body)),
          throwsA(isA<SsbCryptoException>()));
      // control: tuple A opens
      expect(
          (await ItemCryptoV1.open(vaultId: aV, tierKey: tk, item: SealedItem(aI, Tier.ice, wrapped, body))),
          bytes('secret'));
    });
  });

  group('label registry (new builders must be registered here)', () {
    final libDir = Directory('lib');

    test('the set of ctx2 "what" labels in lib/ is exactly the registered one', () {
      final found = <String>{};
      final re = RegExp(r"ctx2\(\s*'([A-Za-z0-9-]+)'");
      for (final f in libDir.listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart'))) {
        for (final line in f.readAsLinesSync()) {
          if (line.trimLeft().startsWith('//')) continue;
          for (final m in re.allMatches(line)) {
            found.add(m.group(1)!);
          }
        }
      }
      expect(found, equals({'vk', 'tk', 'ik', 'item', 'file', 'manifest', 'tier-export'}),
          reason: 'new ctx2 label: add it to the "all v2 builders together" test above, then to this set');
    });

    test('raw "ssb/vN/<label>" literals in lib/ are exactly the registered ones, and prefix-free', () {
      final found = <String>{};
      final re = RegExp(r"'(ssb/v[0-9]/[A-Za-z0-9/_-]*)");
      for (final f in libDir.listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart'))) {
        if (f.path.endsWith('bytes.dart')) continue; // ctx2's own 'ssb/v2/' prefix
        for (final line in f.readAsLinesSync()) {
          if (line.trimLeft().startsWith('//')) continue;
          for (final m in re.allMatches(line)) {
            var l = m.group(1)!;
            if (l.endsWith('/')) l = l.substring(0, l.length - 1);
            found.add(l);
          }
        }
      }
      const registered = {
        // v2 (current)
        'ssb/v2/s2', 'ssb/v2/items-hash', 'ssb/v2/beneficiary-set', 'ssb/v2/share-check',
        'ssb/v2/sig', 'ssb/v2/vault-id', 'ssb/v2/owner-sign', 'ssb/v2/owner-auth',
        'ssb/v2/owner-delete',
        // v1 labels still produced by live code
        'ssb/v1/claim', 'ssb/v1/owner', 'ssb/v1/safety', 'ssb/v1/kit', 'ssb/v1/secret-key',
        'ssb/v1/unlock-key', 'ssb/v1/deny-reason',
        // v1 read paths (legacy_v1.dart, vault.dart legacyVkContext)
        'ssb/v1/share-check', 'ssb/v1/vk', 'ssb/v1/tk', 'ssb/v1/ik', 'ssb/v1/item',
        'ssb/v1/tier-export',
      };
      expect(found, equals(registered),
          reason: 'new label literal: register it and add its builder to the injectivity tests');
      for (final a in registered) {
        for (final b in registered) {
          if (a != b) {
            expect(b.startsWith('$a/') || b == a, isFalse, reason: '$a is a path-prefix of $b');
          }
        }
      }
    });
  });
}
