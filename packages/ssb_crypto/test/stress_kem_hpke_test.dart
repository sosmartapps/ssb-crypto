@Timeout(Duration(minutes: 6))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

/// Well-known X25519 small-order / non-canonical u-coordinates.
final _lowOrder = <String>[
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map(hexDecode).toList();

void main() {
  final r = seeded(3);

  group('X-Wing', () {
    test('200 random round trips (fresh keys each time); shared secrets all distinct', () async {
      final seen = <String>{};
      for (var i = 0; i < 200; i++) {
        final kp = await XWing.generateKeyPair();
        expect(kp.publicKey.length, XWing.publicKeyLength);
        expect(kp.secretKey.length, XWing.secretKeyLength);
        final e = await XWing.encapsulate(kp.publicKey);
        expect(e.ciphertext.length, XWing.ciphertextLength);
        expect(e.sharedSecret.length, XWing.sharedSecretLength);
        expect(await XWing.decapsulate(e.ciphertext, kp.secretKey), e.sharedSecret, reason: 'i=$i');
        seen.add(hexEncode(e.sharedSecret));
      }
      expect(seen.length, 200);
    });

    test('derandomized keygen/encaps are deterministic; random ones are not', () async {
      final seed = rnd(r, 32), coins = rnd(r, 64);
      final a = await XWing.generateKeyPairDerand(seed), b = await XWing.generateKeyPairDerand(seed);
      expect(a.publicKey, b.publicKey);
      final e1 = await XWing.encapsulateDerand(a.publicKey, coins);
      final e2 = await XWing.encapsulateDerand(a.publicKey, coins);
      expect(e1.ciphertext, e2.ciphertext);
      expect(e1.sharedSecret, e2.sharedSecret);
      final e3 = await XWing.encapsulateDerand(a.publicKey, flip(coins, 0));
      final e4 = await XWing.encapsulateDerand(a.publicKey, flip(coins, 63));
      expect(e3.ciphertext, isNot(e1.ciphertext));
      expect(e4.ciphertext, isNot(e1.ciphertext));
      // nondeterministic API
      final cts = <String>{}, sss = <String>{};
      for (var i = 0; i < 25; i++) {
        final e = await XWing.encapsulate(a.publicKey);
        cts.add(hexEncode(e.ciphertext));
        sss.add(hexEncode(e.sharedSecret));
      }
      expect(cts.length, 25);
      expect(sss.length, 25);
      expect((await XWing.generateKeyPairDerand(flip(seed, 3))).publicKey, isNot(a.publicKey));
    });

    test('corrupting EVERY ciphertext byte: no crash, never the original secret, deterministic', () async {
      final kp = await XWing.generateKeyPair();
      final e = await XWing.encapsulate(kp.publicKey);
      final f = Fails();
      for (var i = 0; i < e.ciphertext.length; i++) {
        final bad = flip(e.ciphertext, i);
        try {
          final s1 = await XWing.decapsulate(bad, kp.secretKey);
          f.check(s1.length == 32, 'byte $i: ss length ${s1.length}');
          f.check(!constantTimeEquals(s1, e.sharedSecret), 'byte $i: ORIGINAL SECRET RETURNED');
          final s2 = await XWing.decapsulate(bad, kp.secretKey);
          f.check(constantTimeEquals(s1, s2), 'byte $i: implicit rejection not deterministic');
        } on SsbCryptoException {
          // clean typed rejection is acceptable
        } catch (err) {
          f.add('byte $i: WRONG-ERROR ${err.runtimeType}');
        }
      }
      // multi-byte / structured corruption
      for (final bad in [
        Uint8List(1120),
        Uint8List(1120)..fillRange(0, 1120, 0xff),
        Uint8List.fromList(e.ciphertext.reversed.toList()),
        Uint8List.fromList([...e.ciphertext.sublist(1088), ...e.ciphertext.sublist(0, 1088)]),
      ]) {
        try {
          final s = await XWing.decapsulate(bad, kp.secretKey);
          f.check(!constantTimeEquals(s, e.sharedSecret), 'structured corruption returned original');
        } on SsbCryptoException {
        } catch (err) {
          f.add('structured: WRONG-ERROR ${err.runtimeType}');
        }
      }
      f.done();
    });

    test('wrong recipient key never recovers the secret (50 pairs); wrong sk byte too', () async {
      final f = Fails();
      for (var i = 0; i < 50; i++) {
        final a = await XWing.generateKeyPair(), b = await XWing.generateKeyPair();
        final e = await XWing.encapsulate(a.publicKey);
        final s = await XWing.decapsulate(e.ciphertext, b.secretKey);
        f.check(!constantTimeEquals(s, e.sharedSecret), 'wrong recipient got secret');
        final s2 = await XWing.decapsulate(e.ciphertext, flip(a.secretKey, i % 32));
        f.check(!constantTimeEquals(s2, e.sharedSecret), 'flipped sk got secret');
      }
      f.done();
    });

    test('wrong-length inputs are clean typed errors', () async {
      final kp = await XWing.generateKeyPair();
      final e = await XWing.encapsulate(kp.publicKey);
      final f = Fails();
      for (final n in [0, 1, 1215, 1217, 1184, 2432]) {
        await f.mustFail('pk len $n', () => XWing.encapsulate(Uint8List(n)));
      }
      for (final n in [0, 63, 65]) {
        await f.mustFail('coins len $n', () => XWing.encapsulateDerand(kp.publicKey, Uint8List(n)));
      }
      for (final n in [0, 1119, 1121, 1088]) {
        await f.mustFail('ct len $n', () => XWing.decapsulate(Uint8List(n), kp.secretKey));
      }
      for (final n in [0, 31, 33, 2400]) {
        await f.mustFail('sk len $n', () => XWing.decapsulate(e.ciphertext, Uint8List(n)));
        await f.mustFail('seed len $n', () => XWing.generateKeyPairDerand(Uint8List(n)));
      }
      f.done();
    });

    test('low-order / non-canonical X25519 points in ciphertext or public key: typed error or safe result', () async {
      final kp = await XWing.generateKeyPair();
      final e = await XWing.encapsulate(kp.publicKey);
      final f = Fails();
      for (final p in _lowOrder) {
        final ct = Uint8List.fromList([...e.ciphertext.sublist(0, 1088), ...p]);
        try {
          final s = await XWing.decapsulate(ct, kp.secretKey);
          f.check(s.length == 32, 'ct lowOrder len');
        } on SsbCryptoException {
        } catch (err) {
          f.add('decaps lowOrder ${hexEncode(p).substring(0, 8)}: WRONG-ERROR ${err.runtimeType}');
        }
        final pk = Uint8List.fromList([...kp.publicKey.sublist(0, 1184), ...p]);
        try {
          // X-Wing (draft-10) defines no low-order check; accepting is
          // spec-compliant (ML-KEM half still protects). Just require it works.
          final enc = await XWing.encapsulate(pk);
          f.check(enc.sharedSecret.length == 32, 'low-order encaps ss length');
        } on SsbCryptoException {
        } catch (err) {
          f.add('encaps lowOrder ${hexEncode(p).substring(0, 8)}: WRONG-ERROR ${err.runtimeType}');
        }
      }
      f.done();
    });
  });

  group('HPKE', () {
    test('200 random round trips with random info/aad/plaintext', () async {
      final kp = await XWing.generateKeyPair();
      final seen = <String>{};
      for (var i = 0; i < 200; i++) {
        final pt = rnd(r, r.nextInt(300)), info = rnd(r, r.nextInt(40)), aad = rnd(r, r.nextInt(40));
        final k = i % 10 == 0 ? await XWing.generateKeyPair() : kp;
        final sealed = await Hpke.seal(k.publicKey, pt, info: info, aad: aad);
        expect(sealed.length, 1120 + pt.length + 16);
        expect(await Hpke.open(k.secretKey, sealed, info: info, aad: aad), pt, reason: 'i=$i');
        seen.add(hexEncode(sealed.sublist(0, 64)));
      }
      expect(seen.length, 200);
    });

    test('empty plaintext, empty info/aad round trip; sealing is non-deterministic', () async {
      final kp = await XWing.generateKeyPair();
      final a = await Hpke.seal(kp.publicKey, Uint8List(0));
      final b = await Hpke.seal(kp.publicKey, Uint8List(0));
      expect(a, isNot(b));
      expect(await Hpke.open(kp.secretKey, a), isEmpty);
    });

    test('mismatched info or aad (flip any byte, extend, drop, swap) fails', () async {
      final kp = await XWing.generateKeyPair();
      final info = utf8Bytes('ssb/v1/s2|vault:V|beneficiary:B|tier:ice'), aad = utf8Bytes('aad-context-xyz');
      final sealed = await Hpke.seal(kp.publicKey, rnd(r, 50), info: info, aad: aad);
      final f = Fails();
      for (var i = 0; i < info.length; i++) {
        await f.mustFail('info $i', () => Hpke.open(kp.secretKey, sealed, info: flip(Uint8List.fromList(info), i), aad: aad));
      }
      for (var i = 0; i < aad.length; i++) {
        await f.mustFail('aad $i', () => Hpke.open(kp.secretKey, sealed, info: info, aad: flip(Uint8List.fromList(aad), i)));
      }
      await f.mustFail('no info', () => Hpke.open(kp.secretKey, sealed, aad: aad));
      await f.mustFail('no aad', () => Hpke.open(kp.secretKey, sealed, info: info));
      await f.mustFail('info+0', () => Hpke.open(kp.secretKey, sealed, info: [...info, 0], aad: aad));
      await f.mustFail('swapped', () => Hpke.open(kp.secretKey, sealed, info: aad, aad: info));
      f.done();
    });

    test('corrupting EVERY byte of enc|ct|tag fails cleanly', () async {
      final kp = await XWing.generateKeyPair();
      final info = utf8Bytes('i'), aad = utf8Bytes('a');
      final sealed = await Hpke.seal(kp.publicKey, rnd(r, 24), info: info, aad: aad);
      final f = Fails();
      for (var i = 0; i < sealed.length; i++) {
        await f.mustFail('byte $i', () => Hpke.open(kp.secretKey, flip(sealed, i), info: info, aad: aad));
      }
      f.done();
    });

    test('truncation at every length and extension fail', () async {
      final kp = await XWing.generateKeyPair();
      final sealed = await Hpke.seal(kp.publicKey, rnd(r, 24));
      final f = Fails();
      for (var n = 0; n < sealed.length; n++) {
        await f.mustFail('trunc $n', () => Hpke.open(kp.secretKey, sealed.sublist(0, n)));
      }
      for (final x in [1, 16, 100]) {
        await f.mustFail('extend $x', () => Hpke.open(kp.secretKey, Uint8List.fromList([...sealed, ...Uint8List(x)])));
      }
      f.done();
    });

    test('wrong recipient / wrong secret key length fail', () async {
      final a = await XWing.generateKeyPair(), b = await XWing.generateKeyPair();
      final sealed = await Hpke.seal(a.publicKey, rnd(r, 10));
      final f = Fails();
      await f.mustFail('other recipient', () => Hpke.open(b.secretKey, sealed));
      for (var i = 0; i < 32; i++) {
        await f.mustFail('sk byte $i', () => Hpke.open(flip(a.secretKey, i), sealed));
      }
      for (final n in [0, 31, 33]) {
        await f.mustFail('sk len $n', () => Hpke.open(Uint8List(n), sealed));
      }
      for (final n in [0, 1215, 1217]) {
        await f.mustFail('pk len $n', () => Hpke.seal(Uint8List(n), Uint8List(1)));
      }
      f.done();
    });

    test('key schedule: deterministic; info changes key, nonce and exporter', () async {
      final ss = rnd(r, 32);
      final a = await Hpke.keySchedule(ss, [1, 2, 3], kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);
      final b = await Hpke.keySchedule(ss, [1, 2, 3], kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);
      final c = await Hpke.keySchedule(ss, [1, 2, 4], kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);
      final d = await Hpke.keySchedule(flip(ss, 0), [1, 2, 3], kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);
      final e = await Hpke.keySchedule(ss, [1, 2, 3], kemId: Hpke.kemXWing + 1, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);
      expect(a.key, b.key);
      expect(a.baseNonce, b.baseNonce);
      for (final x in [c, d, e]) {
        expect(x.key, isNot(a.key));
        expect(x.baseNonce, isNot(a.baseNonce));
        expect(x.exporterSecret, isNot(a.exporterSecret));
      }
    });
  });
}
