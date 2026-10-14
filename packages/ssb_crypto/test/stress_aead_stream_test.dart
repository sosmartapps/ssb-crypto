@Timeout(Duration(minutes: 5))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

Future<Uint8List> _sealStream(Uint8List key, Uint8List data, int cs, [List<int> ctx = const []]) =>
    StreamCipher.encrypt(key, data, chunkSize: cs, context: ctx);

void main() {
  final r = seeded(2);

  group('AEAD tamper', () {
    final key = randomBytes(32);
    final ctx = utf8Bytes('vault:V1/item:I1');

    test('round trips, incl. empty plaintext and every ObjectType', () async {
      for (final t in ObjectType.values) {
        for (final n in [0, 1, 15, 16, 17, 255, 256, 4097]) {
          final pt = rnd(r, n);
          final blob = await Aead.seal(key, pt, type: t, context: ctx);
          expect(blob.length, n + Aead.overhead);
          expect(await Aead.open(key, blob, type: t, context: ctx), pt);
        }
      }
    });

    test('EVERY bit of EVERY byte of header|nonce|ct|tag fails to open', () async {
      final pt = rnd(r, 40);
      final blob = await Aead.seal(key, pt, type: ObjectType.item, context: ctx);
      final f = Fails();
      for (var i = 0; i < blob.length; i++) {
        for (var bit = 0; bit < 8; bit++) {
          await f.mustFail('byte $i bit $bit',
              () => Aead.open(key, flip(blob, i, 1 << bit), type: ObjectType.item, context: ctx));
        }
      }
      f.done();
    });

    test('every byte of the AAD context matters; prefix/suffix/empty contexts fail', () async {
      final blob = await Aead.seal(key, rnd(r, 20), type: ObjectType.item, context: ctx);
      final f = Fails();
      for (var i = 0; i < ctx.length; i++) {
        for (final m in [0x01, 0x80, 0xff]) {
          await f.mustFail('ctx byte $i',
              () => Aead.open(key, blob, type: ObjectType.item, context: flip(ctx, i, m)));
        }
      }
      await f.mustFail('empty ctx', () => Aead.open(key, blob, type: ObjectType.item));
      await f.mustFail('prefix ctx', () => Aead.open(key, blob, type: ObjectType.item, context: ctx.sublist(0, ctx.length - 1)));
      await f.mustFail('suffix ctx', () => Aead.open(key, blob, type: ObjectType.item, context: [...ctx, 0]));
      f.done();
    });

    test('type confusion and wrong key (every key byte) fail', () async {
      final blob = await Aead.seal(key, rnd(r, 20), type: ObjectType.item, context: ctx);
      final f = Fails();
      for (final t in ObjectType.values.where((t) => t != ObjectType.item)) {
        await f.mustFail('type ${t.name}', () => Aead.open(key, blob, type: t, context: ctx));
      }
      for (var i = 0; i < 32; i++) {
        await f.mustFail('key byte $i', () => Aead.open(flip(key, i), blob, type: ObjectType.item, context: ctx));
      }
      for (final n in [0, 16, 31, 33, 64]) {
        await f.mustFail('key len $n', () => Aead.open(Uint8List(n), blob, type: ObjectType.item, context: ctx));
        await f.mustFail('seal key len $n', () => Aead.seal(Uint8List(n), Uint8List(1), type: ObjectType.item));
      }
      f.done();
    });

    test('truncation at EVERY length and extension all fail', () async {
      final blob = await Aead.seal(key, rnd(r, 40), type: ObjectType.item, context: ctx);
      final f = Fails();
      for (var n = 0; n < blob.length; n++) {
        await f.mustFail('trunc $n', () => Aead.open(key, blob.sublist(0, n), type: ObjectType.item, context: ctx));
      }
      for (final extra in [1, 2, 12, 16, 32]) {
        await f.mustFail('extend $extra', () => Aead.open(key, Uint8List.fromList([...blob, ...Uint8List(extra)]), type: ObjectType.item, context: ctx));
      }
      // drop first byte(s)
      for (var n = 1; n < 20; n++) {
        await f.mustFail('drop-front $n', () => Aead.open(key, blob.sublist(n), type: ObjectType.item, context: ctx));
      }
      f.done();
    });

    test('nonce, tag and ciphertext cannot be swapped between two valid blobs', () async {
      final a = await Aead.seal(key, rnd(r, 40), type: ObjectType.item, context: ctx);
      final b = await Aead.seal(key, rnd(r, 40), type: ObjectType.item, context: ctx);
      final f = Fails();
      Uint8List splice(Uint8List x, Uint8List y, int from, int to) =>
          Uint8List.fromList([...x.sublist(0, from), ...y.sublist(from, to), ...x.sublist(to)]);
      await f.mustFail('nonce swap', () => Aead.open(key, splice(a, b, 6, 18), type: ObjectType.item, context: ctx));
      await f.mustFail('tag swap', () => Aead.open(key, splice(a, b, a.length - 16, a.length), type: ObjectType.item, context: ctx));
      await f.mustFail('ct swap', () => Aead.open(key, splice(a, b, 18, a.length - 16), type: ObjectType.item, context: ctx));
      f.done();
    });

    test('nonce uniqueness: 10,000 seals under ONE key never repeat a nonce', () async {
      final seen = <String>{};
      for (var i = 0; i < 10000; i++) {
        final b = await Aead.seal(key, Uint8List(0), type: ObjectType.item);
        seen.add(hexEncode(b.sublist(6, 18)));
      }
      expect(seen.length, 10000);
    });

    test('same key + same plaintext never gives the same ciphertext', () async {
      final pt = rnd(r, 64);
      final a = await Aead.seal(key, pt, type: ObjectType.item);
      final b = await Aead.seal(key, pt, type: ObjectType.item);
      expect(a, isNot(b));
    });

    test('explicit nonce of wrong length is a clean typed error', () async {
      final f = Fails();
      for (final n in [0, 1, 11, 13, 16, 32]) {
        await f.mustFail('nonce len $n', () => Aead.seal(key, rnd(r, 8), type: ObjectType.item, nonce: Uint8List(n)));
      }
      f.done();
    });
  });

  group('Vault / ItemCrypto tamper', () {
    test('every byte of wrapped item key and body: open fails; cross-slot moves fail', () async {
      final tk = randomBytes(32);
      final item = await ItemCrypto.seal(
          vaultId: 'V', tier: Tier.secrets, tierKey: tk, itemId: 'I', plaintext: rnd(r, 100));
      final f = Fails();
      for (var i = 0; i < item.wrappedItemKey.length; i++) {
        await f.mustFail('wik $i', () => ItemCrypto.open(vaultId: 'V', tierKey: tk,
            item: SealedItem('I', Tier.secrets, flip(item.wrappedItemKey, i), item.body)));
      }
      for (var i = 0; i < item.body.length; i++) {
        await f.mustFail('body $i', () => ItemCrypto.open(vaultId: 'V', tierKey: tk,
            item: SealedItem('I', Tier.secrets, item.wrappedItemKey, flip(item.body, i))));
      }
      await f.mustFail('other vault', () => ItemCrypto.open(vaultId: 'V2', tierKey: tk, item: item));
      await f.mustFail('other item id', () => ItemCrypto.open(vaultId: 'V', tierKey: tk,
          item: SealedItem('I2', Tier.secrets, item.wrappedItemKey, item.body)));
      await f.mustFail('other tier', () => ItemCrypto.open(vaultId: 'V', tierKey: tk,
          item: SealedItem('I', Tier.ice, item.wrappedItemKey, item.body)));
      await f.mustFail('wrong tier key', () => ItemCrypto.open(vaultId: 'V', tierKey: randomBytes(32), item: item));
      // body from a different item with valid wrapped key
      final other = await ItemCrypto.seal(vaultId: 'V', tier: Tier.secrets, tierKey: tk, itemId: 'I', plaintext: rnd(r, 100));
      await f.mustFail('body swap', () => ItemCrypto.open(vaultId: 'V', tierKey: tk,
          item: SealedItem('I', Tier.secrets, item.wrappedItemKey, other.body)));
      f.done();
    });

    test('padme: >= input, monotone, sizes round trip, empty item ok', () async {
      var prev = 0;
      for (var l = 2; l < 20000; l++) {
        final p = ItemCrypto.padmeLength(l);
        expect(p, greaterThanOrEqualTo(l));
        expect(p, greaterThanOrEqualTo(prev));
        expect(p, lessThan(l * 1.13 + 2));
        prev = p;
      }
      final tk = randomBytes(32);
      for (final n in [0, 1, 251, 252, 253, 255, 256, 1000, 70000]) {
        final pt = rnd(r, n);
        final it = await ItemCrypto.seal(vaultId: 'V', tier: Tier.ice, tierKey: tk, itemId: 'I', plaintext: pt);
        expect(await ItemCrypto.open(vaultId: 'V', tierKey: tk, item: it), pt);
      }
    });

    test('authentic body with a lying length prefix is a clean error', () async {
      final tk = randomBytes(32);
      final ik = randomBytes(32);
      final wik = await Aead.seal(tk, ik,
          type: ObjectType.wrappedKey, context: utf8Bytes('ssb/v1/ik|vault:V|tier:ice|item:I'));
      final f = Fails();
      for (final p in [
        Uint8List.fromList([0xff, 0xff, 0xff, 0xff, 1, 2, 3]),
        Uint8List.fromList([0, 0, 0, 4, 1, 2, 3]),
        Uint8List.fromList([1, 2, 3]),
        Uint8List(0),
        Uint8List.fromList([0x80, 0, 0, 0]),
      ]) {
        final body = await Aead.seal(ik, p, type: ObjectType.item, context: utf8Bytes('ssb/v1/item|vault:V|item:I'));
        await f.mustFail('prefix ${hexEncode(p)}', () => ItemCrypto.open(
            vaultId: 'V', tierKey: tk, item: SealedItem('I', Tier.ice, wik, body)));
      }
      f.done();
    });

    test('keyring: wrapped vault/tier keys fail under any byte flip, wrong slot, wrong vault', () async {
      final ring = VaultKeyring.create('V');
      final kek = randomBytes(32);
      final wvk = await ring.wrapVaultKey(kek, slot: 'unlock');
      final wtk = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
      final f = Fails();
      for (var i = 0; i < wvk.length; i++) {
        await f.mustFail('wvk $i', () => VaultKeyring.open(vaultId: 'V', kek: kek, slot: 'unlock',
            wrappedVaultKey: flip(wvk, i), wrappedTierKeys: wtk));
      }
      for (final t in Tier.values) {
        for (var i = 0; i < wtk[t]!.length; i += 3) {
          await f.mustFail('wtk ${t.name} $i', () => VaultKeyring.open(vaultId: 'V', kek: kek, slot: 'unlock',
              wrappedVaultKey: wvk, wrappedTierKeys: {...wtk, t: flip(wtk[t]!, i)}));
        }
      }
      // tier key wrapped for ice presented as secrets
      await f.mustFail('tier swap', () => VaultKeyring.open(vaultId: 'V', kek: kek, slot: 'unlock',
          wrappedVaultKey: wvk, wrappedTierKeys: {Tier.secrets: wtk[Tier.ice]!}));
      f.done();
    });
  });

  group('STREAM', () {
    final key = randomBytes(32);
    const tag = 16, head = 6 + 7 + 4;

    test('boundary sizes around the DEFAULT 64 KiB chunk round trip', () async {
      const cs = StreamCipher.defaultChunkSize;
      for (final n in [0, 1, cs - 1, cs, cs + 1, 2 * cs]) {
        final data = rnd(r, n);
        final blob = await StreamCipher.encrypt(key, data);
        final chunks = n == 0 ? 1 : (n + cs - 1) ~/ cs;
        expect(blob.length, head + n + chunks * tag, reason: 'n=$n');
        expect(await StreamCipher.decrypt(key, blob), data, reason: 'n=$n');
      }
    });

    test('boundary sizes around small chunk sizes round trip', () async {
      for (final cs in [1, 2, 7, 16, 64]) {
        for (final n in [0, 1, cs - 1, cs, cs + 1, 2 * cs, 3 * cs + 1]) {
          if (n < 0) continue;
          final data = rnd(r, n);
          expect(await StreamCipher.decrypt(key, await _sealStream(key, data, cs)), data, reason: 'cs=$cs n=$n');
        }
      }
    });

    test('EVERY byte x EVERY bit of header/prefix/chunk-size/chunks/tags fails', () async {
      const cs = 16;
      final ctx = utf8Bytes('file:F1');
      for (final n in [0, 1, 16, 17, 40]) {
        final blob = await _sealStream(key, rnd(r, n), cs, ctx);
        final f = Fails();
        for (var i = 0; i < blob.length; i++) {
          for (var bit = 0; bit < 8; bit++) {
            await f.mustFail('n=$n byte $i bit $bit',
                () => StreamCipher.decrypt(key, flip(blob, i, 1 << bit), context: ctx));
          }
        }
        f.done();
      }
    });

    test('context bytes, wrong key, truncation at EVERY length, extension', () async {
      const cs = 16;
      final ctx = utf8Bytes('file:F1');
      for (final n in [0, 5, 16, 33, 48]) {
        final blob = await _sealStream(key, rnd(r, n), cs, ctx);
        final f = Fails();
        for (var i = 0; i < ctx.length; i++) {
          await f.mustFail('ctx $i', () => StreamCipher.decrypt(key, blob, context: flip(ctx, i)));
        }
        await f.mustFail('no ctx', () => StreamCipher.decrypt(key, blob));
        await f.mustFail('wrong key', () => StreamCipher.decrypt(randomBytes(32), blob, context: ctx));
        for (var len = 0; len < blob.length; len++) {
          await f.mustFail('n=$n trunc $len', () => StreamCipher.decrypt(key, blob.sublist(0, len), context: ctx));
        }
        for (final extra in [1, 15, 16, 17, 32]) {
          await f.mustFail('n=$n extend $extra', () => StreamCipher.decrypt(
              key, Uint8List.fromList([...blob, ...rnd(r, extra)]), context: ctx));
        }
        f.done();
      }
    });

    test('chunk reorder / duplicate / remove / splice / cross-file', () async {
      const cs = 16;
      const w = cs + tag;
      // 4 chunks: 3 full + final of 5 bytes
      final data = rnd(r, 3 * cs + 5);
      final blob = await _sealStream(key, data, cs);
      final h = blob.sublist(0, head);
      Uint8List chunk(Uint8List b, int i) => b.sublist(head + i * w, i == 3 ? b.length : head + (i + 1) * w);
      final c = [for (var i = 0; i < 4; i++) chunk(blob, i)];
      Uint8List build(Uint8List hh, List<Uint8List> cc) =>
          Uint8List.fromList([...hh, for (final x in cc) ...x]);
      expect(await StreamCipher.decrypt(key, build(h, c)), data); // sanity

      final f = Fails();
      final cases = <String, List<Uint8List>>{
        'swap 0,1': [c[1], c[0], c[2], c[3]],
        'swap 1,2': [c[0], c[2], c[1], c[3]],
        'dup 0': [c[0], c[0], c[1], c[2], c[3]],
        'dup 1': [c[0], c[1], c[1], c[2], c[3]],
        'dup mid replaces next': [c[0], c[1], c[1], c[3]],
        'remove 0': [c[1], c[2], c[3]],
        'remove 1': [c[0], c[2], c[3]],
        'remove 2': [c[0], c[1], c[3]],
        'remove last (truncate)': [c[0], c[1], c[2]],
        'last moved to front': [c[3], c[0], c[1], c[2]],
        'append dup of first after last': [...c, c[0]],
        'append dup of last': [...c, c[3]],
        'only last': [c[3]],
        'only first': [c[0]],
        'reverse': c.reversed.toList(),
      };
      for (final e in cases.entries) {
        await f.mustFail(e.key, () => StreamCipher.decrypt(key, build(h, e.value)));
      }
      // Cross-file: same key, different random prefix. Chunks from file B in A.
      final other = await _sealStream(key, data, cs);
      final oc = [for (var i = 0; i < 4; i++) chunk(other, i)];
      for (var i = 0; i < 4; i++) {
        final mixed = [...c]..[i] = oc[i];
        await f.mustFail('splice B chunk $i into A', () => StreamCipher.decrypt(key, build(h, mixed)));
      }
      await f.mustFail('B body under A header', () => StreamCipher.decrypt(key, build(h, oc)));
      // Header from A, all chunks from A but first chunk-size field swapped
      for (final newCs in [0, 1, 15, 17, 32, 0xffffffff, 0x01000001, 0x80000000]) {
        final hh = Uint8List.fromList(h)..setRange(13, 17, u32be(newCs));
        await f.mustFail('chunk size field -> $newCs', () => StreamCipher.decrypt(key, build(hh, c)));
      }
      f.done();
    });

    test('STREAM prefix (per-file nonce) unique over 2,000 encryptions', () async {
      final seen = <String>{};
      for (var i = 0; i < 2000; i++) {
        final b = await _sealStream(key, Uint8List(0), 16);
        seen.add(hexEncode(b.sublist(6, 13)));
      }
      expect(seen.length, 2000);
    });

    test('bad encrypt inputs are clean typed errors', () async {
      final f = Fails();
      await f.mustFail('chunk 0', () => StreamCipher.encrypt(key, Uint8List(3), chunkSize: 0));
      await f.mustFail('chunk -1', () => StreamCipher.encrypt(key, Uint8List(3), chunkSize: -1));
      await f.mustFail('short key', () => StreamCipher.encrypt(Uint8List(31), Uint8List(3)));
      await f.mustFail('short key dec', () => StreamCipher.decrypt(Uint8List(31), Uint8List(100)));
      f.done();
    });

    test('files via ItemCrypto: tamper every 7th byte, wrong ids', () async {
      final tk = randomBytes(32);
      final (wk, st) = await ItemCrypto.sealFile(
          vaultId: 'V', tier: Tier.essentials, tierKey: tk, fileId: 'F', data: rnd(r, 700));
      expect(await ItemCrypto.openFile(vaultId: 'V', tier: Tier.essentials, tierKey: tk, fileId: 'F', wrappedKey: wk, stream: st), hasLength(700));
      final f = Fails();
      for (var i = 0; i < st.length; i += 7) {
        await f.mustFail('stream $i', () => ItemCrypto.openFile(vaultId: 'V', tier: Tier.essentials, tierKey: tk, fileId: 'F', wrappedKey: wk, stream: flip(st, i)));
      }
      await f.mustFail('file id', () => ItemCrypto.openFile(vaultId: 'V', tier: Tier.essentials, tierKey: tk, fileId: 'G', wrappedKey: wk, stream: st));
      await f.mustFail('tier', () => ItemCrypto.openFile(vaultId: 'V', tier: Tier.ice, tierKey: tk, fileId: 'F', wrappedKey: wk, stream: st));
      await f.mustFail('vault', () => ItemCrypto.openFile(vaultId: 'W', tier: Tier.essentials, tierKey: tk, fileId: 'F', wrappedKey: wk, stream: st));
      f.done();
    });
  });
}
