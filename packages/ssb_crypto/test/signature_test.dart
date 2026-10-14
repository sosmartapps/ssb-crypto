import 'dart:convert';
import 'dart:typed_data';

import 'package:mldsa_native/mldsa65.dart';
import 'package:pqcrypto/pqcrypto.dart';
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  final params = DilithiumParams.get(DilithiumParameter.mlDsa65);

  group('ML-DSA-65 cross-implementation checks (native C vs pure Dart)', () {
    test('seeded key generation agrees', () {
      final seed = randomBytes(32);
      final native = MLDSA65().generateKeyPair(coins: seed);
      final (pk, sk) = MlDsa.generateKeyPairSeeded(params, seed);
      expect(hexEncode(native.publicKey), hexEncode(pk));
      expect(hexEncode(native.secretKey), hexEncode(sk));
    });

    test('signatures made by each implementation verify in the other', () {
      final seed = randomBytes(32);
      final native = MLDSA65().generateKeyPair(coins: seed);
      final msg = Uint8List.fromList(utf8.encode('release token for vault v1'));
      final nativeSig = MLDSA65().sign(native.secretKey, msg);
      expect(MlDsa.verify(native.publicKey, msg, nativeSig, params), isTrue);
      final dartSig = MlDsa.sign(native.secretKey, msg, params);
      expect(MLDSA65().verify(native.publicKey, msg, dartSig), isTrue);
    });

    test('a modified message is rejected by both', () {
      final native = MLDSA65().generateKeyPair(coins: randomBytes(32));
      final msg = Uint8List.fromList(utf8.encode('release at 12:00'));
      final sig = MLDSA65().sign(native.secretKey, msg);
      final tampered = Uint8List.fromList(utf8.encode('release at 13:00'));
      expect(MLDSA65().verify(native.publicKey, tampered, sig), isFalse);
      expect(MlDsa.verify(native.publicKey, tampered, sig, params), isFalse);
    });
  });

  group('Hybrid Ed25519 + ML-DSA-65', () {
    test('sizes are fixed and documented', () async {
      final kp = await HybridSignature.generateKeyPair();
      expect(kp.publicKey.length, HybridSignature.publicKeyLength);
      expect(kp.secretKey.length, HybridSignature.secretKeyLength);
      final sig = await HybridSignature.sign(kp.secretKey, Uint8List(10), purpose: 'test');
      expect(sig.length, HybridSignature.signatureLength);
    });

    test('round trip, and purpose is bound in', () async {
      final kp = await HybridSignature.generateKeyPair();
      final msg = Uint8List.fromList(utf8.encode('{"tier":"secrets","release":true}'));
      final sig = await HybridSignature.sign(kp.secretKey, msg, purpose: 'release-token');
      expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: 'release-token'), isTrue);
      // The same signature must not be replayable as another kind of statement.
      expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: 'audit-entry'), isFalse);
    });

    test('both halves must be intact: forging one algorithm is not enough', () async {
      final a = await HybridSignature.generateKeyPair();
      final b = await HybridSignature.generateKeyPair();
      final msg = Uint8List.fromList(utf8.encode('grant access'));
      final sigA = await HybridSignature.sign(a.secretKey, msg, purpose: 'p');
      final sigB = await HybridSignature.sign(b.secretKey, msg, purpose: 'p');
      // Valid Ed25519 half from A + ML-DSA half from B, and vice versa.
      final mixed1 = Uint8List.fromList(
          [...sigA.sublist(0, 64), ...sigB.sublist(64)]);
      final mixed2 = Uint8List.fromList(
          [...sigB.sublist(0, 64), ...sigA.sublist(64)]);
      expect(await HybridSignature.verify(a.publicKey, msg, mixed1, purpose: 'p'), isFalse);
      expect(await HybridSignature.verify(a.publicKey, msg, mixed2, purpose: 'p'), isFalse);
      // Wrong signer, tampered message, truncated signature.
      expect(await HybridSignature.verify(b.publicKey, msg, sigA, purpose: 'p'), isFalse);
      expect(await HybridSignature.verify(a.publicKey, Uint8List.fromList([...msg, 1]), sigA, purpose: 'p'), isFalse);
      expect(await HybridSignature.verify(a.publicKey, msg, sigA.sublist(0, 100), purpose: 'p'), isFalse);
    });
  });
}
