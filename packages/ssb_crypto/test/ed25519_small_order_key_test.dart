// Small-order / torsion Ed25519 public keys (report by hrydarie, 2026-11-03).
//
// package:cryptography's Ed25519 verifier does not check the public key, so
// for the identity point the pair (R = B, S = 1) verifies for every message
// with no secret. HybridSignature.verify and OwnerIdentity.verifyChallenge
// must refuse such keys; honest keys must keep working.
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:ssb_crypto/src/ed25519_key_check.dart';
import 'package:ssb_crypto/src/pq/pq.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Uint8List _hex(String h) => Uint8List.fromList(List.generate(
    h.length ~/ 2, (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16)));

Uint8List _le(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  for (var i = 0; i < 32; i++) {
    out[i] = (x & BigInt.from(255)).toInt();
    x >>= 8;
  }
  return out;
}

final _p = (BigInt.one << 255) - BigInt.from(19);
// Base point B encoding: y = 4/5, sign 0.
final _basePoint = _hex('58${'66' * 31}');
// Small-order points: identity (order 1), (0,-1) (order 2), order 4, order 8.
final _identity = _le(BigInt.one);
final _order2 = _le(_p - BigInt.one);
final _order4 = Uint8List(32); // y = 0, x = +sqrt(-1), sign bit 0
final _order4b = _hex('${'00' * 31}80'); // y = 0, sign bit 1
final _order8 = _hex(
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');
final _order8b = _hex(
    'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa');

void main() {
  group('Ed25519KeyCheck.isValidPublicKey', () {
    test('accepts honest keys (100 random seeds)', () async {
      final ed = Ed25519();
      for (var i = 0; i < 100; i++) {
        final kp = await ed.newKeyPairFromSeed(randomBytes(32));
        final pk = (await kp.extractPublicKey()).bytes;
        expect(Ed25519KeyCheck.isValidPublicKey(pk), isTrue);
      }
      expect(Ed25519KeyCheck.isValidPublicKey(_basePoint), isTrue);
    });

    test('rejects the identity and every small-order point', () {
      for (final k in [_identity, _order2, _order4, _order4b, _order8, _order8b]) {
        expect(Ed25519KeyCheck.isValidPublicKey(k), isFalse, reason: '$k');
      }
    });

    test('rejects a key with a torsion component (B + order-8 point)', () {
      // A = B + T8 is on the curve with [L]A = T8 != identity. Built by
      // adding the points in affine form.
      final a = _addPoints(_basePoint, _order8);
      expect(Ed25519KeyCheck.isValidPublicKey(a), isFalse);
    });

    test('rejects non-canonical and malformed encodings', () {
      // y = 1 + p is the identity written non-canonically.
      expect(Ed25519KeyCheck.isValidPublicKey(_le(_p + BigInt.one)), isFalse);
      // identity with the sign bit set (x = 0 cannot be negative).
      final idNeg = Uint8List.fromList(_identity)..[31] |= 0x80;
      expect(Ed25519KeyCheck.isValidPublicKey(idNeg), isFalse);
      // y = 2 is not on the curve.
      expect(Ed25519KeyCheck.isValidPublicKey(_le(BigInt.two)), isFalse);
      expect(Ed25519KeyCheck.isValidPublicKey(Uint8List(31)), isFalse);
      expect(Ed25519KeyCheck.isValidPublicKey(Uint8List(33)), isFalse);
      expect(Ed25519KeyCheck.isValidPublicKey(Uint8List(32)), isFalse); // y = 0 is order 4
    });
  });

  group('the underlying library accepts the forgery (documents the cause)', () {
    test('raw Ed25519 verify under the identity key', () async {
      final sig = Signature(Uint8List.fromList([..._basePoint, ..._le(BigInt.one)]),
          publicKey: SimplePublicKey(_identity, type: KeyPairType.ed25519));
      expect(await Ed25519().verify(utf8Bytes('any message'), signature: sig), isTrue);
    });
  });

  group('HybridSignature', () {
    late HybridKeyPair kp;
    final msg = utf8Bytes('enrolment record: beneficiary B, tier secrets');
    const purpose = 'enrollment';
    setUpAll(() async => kp = await HybridSignature.generateKeyPair());

    // ML-DSA half signed honestly with the composite key's own ML-DSA secret:
    // what a malicious enrolment would present. Only the Ed25519 half is forged.
    Uint8List forged(Uint8List weakEdPk, Uint8List r, BigInt s) {
      final dm = concatBytes(
          [utf8Bytes('ssb/v2/sig'), u16be(utf8Bytes(purpose).length), utf8Bytes(purpose), msg]);
      final dsa = MlDsa65.sign(
          Uint8List.fromList(kp.secretKey.sublist(HybridSignature.edSkLen)), dm);
      return concatBytes([r, _le(s), dsa]);
    }

    Uint8List weakKey(Uint8List ed) =>
        concatBytes([ed, kp.publicKey.sublist(HybridSignature.edPkLen)]);

    test('honest signature still verifies', () async {
      final sig = await HybridSignature.sign(kp.secretKey, msg, purpose: purpose);
      expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: purpose), isTrue);
      HybridSignature.validatePublicKey(kp.publicKey);
    });

    test('identity-A forgery (R = B, S = 1) is rejected', () async {
      final pk = weakKey(_identity);
      final sig = forged(_identity, _basePoint, BigInt.one);
      expect(await HybridSignature.verify(pk, msg, sig, purpose: purpose), isFalse);
      expect(() => HybridSignature.validatePublicKey(pk), throwsA(isA<SsbCryptoException>()));
    });

    test('order-2-A forgery is rejected', () async {
      final pk = weakKey(_order2);
      // R = [k]B, S = k verifies when h is even; try small k until the
      // library accepts it, then require that our verifier refuses it.
      final ed = Ed25519();
      var libraryAccepted = false;
      for (var k = 1; k < 64 && !libraryAccepted; k++) {
        final r = _scalarBase(k);
        final sig = forged(_order2, r, BigInt.from(k));
        final raw = await ed.verify(concatBytes([utf8Bytes('ssb/v2/sig'),
              u16be(utf8Bytes(purpose).length), utf8Bytes(purpose), msg]),
            signature: Signature(sig.sublist(0, 64),
                publicKey: SimplePublicKey(_order2, type: KeyPairType.ed25519)));
        if (raw) {
          libraryAccepted = true;
          expect(await HybridSignature.verify(pk, msg, sig, purpose: purpose), isFalse);
        }
      }
      expect(libraryAccepted, isTrue, reason: 'no forgery found to test against');
    });

    test('torsion-component key is rejected', () async {
      final pk = weakKey(_addPoints(_basePoint, _order8));
      expect(() => HybridSignature.validatePublicKey(pk), throwsA(isA<SsbCryptoException>()));
    });
  });

  group('OwnerIdentity.verifyChallenge', () {
    test('forged challenge under the identity key is rejected', () async {
      final nonce = randomBytes(32);
      final id = OwnerIdentity.vaultIdFor(_identity);
      final ok = await OwnerIdentity.verifyChallenge(
          publicKey: _identity,
          vaultId: id,
          nonce: nonce,
          signature: Uint8List.fromList([..._basePoint, ..._le(BigInt.one)]));
      expect(ok, isFalse);
    });

    test('an honest owner still signs in', () async {
      final vk = randomBytes(32);
      final owner = await OwnerIdentity.derive(vk);
      final nonce = randomBytes(32);
      final sig = await OwnerIdentity.signChallenge(
          vaultKey: vk, vaultId: owner.vaultId, nonce: nonce);
      expect(
          await OwnerIdentity.verifyChallenge(
              publicKey: owner.publicKey, vaultId: owner.vaultId, nonce: nonce, signature: sig),
          isTrue);
    });
  });
}

// --- minimal affine Edwards arithmetic for building test points ---
final _d = (BigInt.from(-121665) * BigInt.from(121666).modInverse(_p)) % _p;

(BigInt, BigInt) _decode(Uint8List e) {
  var y = BigInt.zero;
  for (var i = 31; i >= 0; i--) {
    y = (y << 8) | BigInt.from(e[i]);
  }
  final sign = (y >> 255).toInt();
  y &= (BigInt.one << 255) - BigInt.one;
  final x2 = ((y * y - BigInt.one) * ((_d * y * y + BigInt.one).modInverse(_p))) % _p;
  var x = x2.modPow((_p + BigInt.from(3)) ~/ BigInt.from(8), _p);
  if ((x * x - x2) % _p != BigInt.zero) {
    x = (x * BigInt.two.modPow((_p - BigInt.one) ~/ BigInt.from(4), _p)) % _p;
  }
  if (x.isOdd != (sign == 1)) x = _p - x;
  return (x, y);
}

Uint8List _encode((BigInt, BigInt) pt) {
  final out = _le(pt.$2);
  if (pt.$1.isOdd) out[31] |= 0x80;
  return out;
}

(BigInt, BigInt) _addAff((BigInt, BigInt) a, (BigInt, BigInt) b) {
  final t = _d * a.$1 * b.$1 * a.$2 * b.$2;
  final x = ((a.$1 * b.$2 + b.$1 * a.$2) * (BigInt.one + t).modInverse(_p)) % _p;
  final y = ((a.$2 * b.$2 + a.$1 * b.$1) * (BigInt.one - t).modInverse(_p)) % _p;
  return (x, y);
}

Uint8List _addPoints(Uint8List a, Uint8List b) => _encode(_addAff(_decode(a), _decode(b)));

Uint8List _scalarBase(int k) {
  var r = (BigInt.zero, BigInt.one);
  final b = _decode(_basePoint);
  for (var i = 0; i < k; i++) {
    r = _addAff(r, b);
  }
  return _encode(r);
}
