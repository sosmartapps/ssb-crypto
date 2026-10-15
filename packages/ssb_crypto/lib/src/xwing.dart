import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/digests/sha3.dart';

import 'bytes.dart';
import 'pq/pq.dart';

/// X-Wing hybrid KEM: ML-KEM-768 + X25519 (draft-connolly-cfrg-xwing-kem).
///
/// Secure as long as either ML-KEM-768 or X25519 holds, so data sealed today
/// survives a future quantum computer ("harvest now, decrypt later").
/// Validated against the draft's test vectors (test/xwing_test.dart).
class XWingKeyPair {
  /// 32-byte seed; the full decapsulation key is re-expanded from it.
  final Uint8List secretKey;

  /// 1216-byte encapsulation key: ML-KEM-768 pk (1184) || X25519 pk (32).
  final Uint8List publicKey;
  XWingKeyPair(this.secretKey, this.publicKey);
}

class XWingEncapsulation {
  final Uint8List sharedSecret; // 32 bytes
  final Uint8List ciphertext; // 1120 bytes
  XWingEncapsulation(this.sharedSecret, this.ciphertext);
}

abstract final class XWing {
  static const secretKeyLength = 32;
  static const publicKeyLength = 1216;
  static const ciphertextLength = 1120;
  static const sharedSecretLength = 32;
  static const _label = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]; // \.//^\

  static final _x25519 = X25519();

  static Future<XWingKeyPair> generateKeyPair() =>
      generateKeyPairDerand(randomBytes(secretKeyLength));

  static Future<XWingKeyPair> generateKeyPairDerand(Uint8List seed) async {
    if (seed.length != secretKeyLength) throw const SsbCryptoException('bad seed');
    // Copy before the first await so the returned secret key and the public
    // key always come from the same seed bytes (see Aead.seal).
    final sk = Uint8List.fromList(seed);
    final e = await _expand(sk);
    try {
      return XWingKeyPair(sk, concatBytes([e.pkM, e.pkX]));
    } finally {
      e.wipe();
    }
  }

  static Future<XWingEncapsulation> encapsulate(Uint8List publicKey) =>
      encapsulateDerand(publicKey, randomBytes(64));

  static Future<XWingEncapsulation> encapsulateDerand(
      Uint8List publicKey, Uint8List eseed) async {
    if (publicKey.length != publicKeyLength || eseed.length != 64) {
      throw const SsbCryptoException('bad encapsulation input');
    }
    final pkM = Uint8List.sublistView(publicKey, 0, 1184);
    final pkX = Uint8List.sublistView(publicKey, 1184, 1216);
    final ekX = Uint8List.fromList(eseed.sublist(32, 64));
    final ctX = await _x25519Public(ekX);
    final ssX = await _x25519Shared(ekX, pkX);
    final Uint8List ctM, ssM;
    try {
      (ctM, ssM) = MlKem768.encaps(
          Uint8List.fromList(pkM), Uint8List.fromList(eseed.sublist(0, 32)));
    } on SsbCryptoException {
      rethrow;
    } catch (_) {
      // Invalid ML-KEM public key (failed modulus check etc.): surface the
      // package's one typed error, not the native binding's exception.
      wipe(ekX);
      wipe(ssX);
      throw const SsbCryptoException('bad encapsulation input');
    }
    final ss = _combiner(ssM, ssX, ctX, pkX);
    wipe(ekX);
    wipe(ssX);
    wipe(ssM);
    return XWingEncapsulation(ss, concatBytes([ctM, ctX]));
  }

  static Future<Uint8List> decapsulate(
      Uint8List ciphertext, Uint8List secretKey) async {
    if (ciphertext.length != ciphertextLength || secretKey.length != secretKeyLength) {
      throw const SsbCryptoException('bad decapsulation input');
    }
    final e = await _expand(secretKey);
    try {
      final ctM = Uint8List.fromList(ciphertext.sublist(0, 1088));
      final ctX = Uint8List.fromList(ciphertext.sublist(1088, 1120));
      final ssM = MlKem768.decaps(ctM, e.skM);
      final ssX = await _x25519Shared(e.skX, ctX);
      final ss = _combiner(ssM, ssX, ctX, e.pkX);
      wipe(ssM);
      wipe(ssX);
      return ss;
    } finally {
      e.wipe();
    }
  }

  static Future<_Expanded> _expand(Uint8List seed) async {
    final expanded = shake256(seed, 96);
    final (pkM, skM) = MlKem768.keyGen(Uint8List.fromList(expanded.sublist(0, 64)));
    final skX = Uint8List.fromList(expanded.sublist(64, 96));
    final pkX = await _x25519Public(skX);
    wipe(expanded);
    return _Expanded(skM, skX, pkM, pkX);
  }

  static Uint8List _combiner(
      Uint8List ssM, Uint8List ssX, Uint8List ctX, Uint8List pkX) {
    final input = concatBytes([ssM, ssX, ctX, pkX, _label]);
    final d = SHA3Digest(256)..update(input, 0, input.length);
    final out = Uint8List(32);
    d.doFinal(out, 0);
    wipe(input);
    return out;
  }

  static Future<Uint8List> _x25519Public(Uint8List sk) async {
    final kp = await _x25519.newKeyPairFromSeed(sk);
    return Uint8List.fromList((await kp.extractPublicKey()).bytes);
  }

  static Future<Uint8List> _x25519Shared(Uint8List sk, Uint8List pk) async {
    final kp = await _x25519.newKeyPairFromSeed(sk);
    final s = await _x25519.sharedSecretKey(
        keyPair: kp, remotePublicKey: SimplePublicKey(pk, type: KeyPairType.x25519));
    return Uint8List.fromList(await s.extractBytes());
  }
}

class _Expanded {
  final Uint8List skM, skX, pkM, pkX;
  _Expanded(this.skM, this.skX, this.pkM, this.pkX);
  void wipe() {
    skM.fillRange(0, skM.length, 0);
    skX.fillRange(0, skX.length, 0);
  }
}
