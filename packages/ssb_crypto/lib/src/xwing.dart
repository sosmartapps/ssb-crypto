import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartX25519;
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

  static X25519 _x25519 = X25519();
  static String _x25519Backend = 'Dart (package:cryptography)';

  /// Which X25519 implementation X-Wing is using right now (for the
  /// on-device self-test screen).
  static String get x25519Backend => _x25519Backend;

  /// Swaps in a faster X25519 (e.g. Apple CryptoKit via cryptography_flutter).
  ///
  /// Fail-closed: the candidate is installed ONLY if it reproduces the RFC 7748
  /// section 6.1 Diffie-Hellman vector in both directions and agrees with the
  /// pure-Dart reference on [crossChecks] random key pairs. Otherwise the
  /// current implementation is kept and false is returned -- a wrong X25519
  /// would make sealed data unrecoverable, so a mismatch must never install.
  static Future<bool> installX25519(X25519 candidate,
      {required String name, int crossChecks = 4}) async {
    try {
      if (!await _x25519Agrees(candidate, crossChecks)) return false;
    } catch (_) {
      return false;
    }
    _x25519 = candidate;
    _x25519Backend = name;
    return true;
  }

  /// Restores the pure-Dart X25519 (tests, or after a failed self-test).
  static void resetX25519() {
    _x25519 = const DartX25519();
    _x25519Backend = 'Dart (package:cryptography)';
  }

  static Future<bool> _x25519Agrees(X25519 c, int crossChecks) async {
    // RFC 7748 section 6.1.
    final aSk = hexDecode('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    final aPk = hexDecode('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    final bSk = hexDecode('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    final bPk = hexDecode('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const k = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
    if (hexEncode(await _x25519PublicWith(c, aSk)) != hexEncode(aPk)) return false;
    if (hexEncode(await _x25519PublicWith(c, bSk)) != hexEncode(bPk)) return false;
    if (hexEncode(await _x25519SharedWith(c, aSk, bPk)) != k) return false;
    if (hexEncode(await _x25519SharedWith(c, bSk, aPk)) != k) return false;
    const ref = DartX25519();
    for (var i = 0; i < crossChecks; i++) {
      final sk = randomBytes(32);
      final peer = await _x25519PublicWith(ref, randomBytes(32));
      final want = await _x25519SharedWith(ref, sk, peer);
      final got = await _x25519SharedWith(c, sk, peer);
      final same = constantTimeEquals(want, got);
      wipe(sk);
      wipe(want);
      wipe(got);
      if (!same) return false;
    }
    return true;
  }

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

  /// Rejects an X-Wing public key that is the wrong length, or whose ML-KEM
  /// half or X25519 half is all zeros, with [SsbCryptoException].
  ///
  /// Tripwire in the style of Aead's key check: a real key half is all-zero
  /// with probability 2^-256, so one can only be a buffer that was wiped
  /// before it was used. It matters more here than for a symmetric key: a
  /// message sealed to the zero key is readable by ANYONE with no secret at
  /// all -- ML-KEM with t = 0 puts the message straight into the ciphertext,
  /// and X25519 with pk = 0 gives ss = 0, so the combiner needs nothing
  /// secret (red team 2026-10-20, finding B1, PoC redteam_zero_pk_poc_test).
  /// [Hpke.seal] and [Release.create] call this before doing any work.
  static void validatePublicKey(Uint8List publicKey) {
    if (publicKey.length != publicKeyLength) {
      throw const SsbCryptoException('bad public key');
    }
    if (isAllZero(Uint8List.sublistView(publicKey, 0, 1184)) ||
        isAllZero(Uint8List.sublistView(publicKey, 1184, 1216))) {
      throw const SsbCryptoException('bad public key');
    }
  }

  static Future<XWingEncapsulation> encapsulateDerand(
      Uint8List publicKey, Uint8List eseed) async {
    if (eseed.length != 64) {
      throw const SsbCryptoException('bad encapsulation input');
    }
    // Snapshot the recipient key and the randomness BEFORE the first await,
    // then validate the copy (SSB-2026-001 shape, red team 2026-10-26): the
    // old code validated the caller's buffer, then read pkM / pkX from it
    // again after awaiting the X25519 steps, so a wipe landing in between
    // sealed to a zero ML-KEM half (publicly decryptable) or to a zero X25519
    // half (a share nobody can open) with no error.
    final pk = Uint8List.fromList(publicKey);
    final es = Uint8List.fromList(eseed);
    validatePublicKey(pk);
    final pkM = Uint8List.sublistView(pk, 0, 1184);
    final pkX = Uint8List.sublistView(pk, 1184, 1216);
    final ekX = Uint8List.fromList(es.sublist(32, 64));
    final mseed = Uint8List.fromList(es.sublist(0, 32));
    wipe(es);
    final ctX = await _x25519Public(ekX);
    final ssX = await _x25519Shared(ekX, pkX);
    // X25519 returns all zeros for a low-order peer point (RFC 7748 s6.1 lets
    // a receiver check for this). A genuine public key never does, so this
    // can only be a degenerate pkX that slipped past the zero check above.
    if (isAllZero(ssX)) {
      wipe(ekX);
      wipe(ssX);
      wipe(mseed);
      throw const SsbCryptoException('bad public key');
    }
    final Uint8List ctM, ssM;
    try {
      (ctM, ssM) = MlKem768.encaps(Uint8List.fromList(pkM), Uint8List.fromList(mseed));
    } on SsbCryptoException {
      wipe(mseed);
      rethrow;
    } catch (_) {
      // Invalid ML-KEM public key (failed modulus check etc.): surface the
      // package's one typed error, not the native binding's exception.
      wipe(ekX);
      wipe(ssX);
      wipe(mseed);
      throw const SsbCryptoException('bad encapsulation input');
    }
    wipe(mseed);
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
    // Snapshot the ciphertext before the first await: it is read after
    // _expand() has yielded, and an ML-KEM decapsulation of different bytes
    // does not fail, it silently returns a different shared secret.
    final ct = Uint8List.fromList(ciphertext);
    final e = await _expand(secretKey);
    try {
      final ctM = Uint8List.fromList(ct.sublist(0, 1088));
      final ctX = Uint8List.fromList(ct.sublist(1088, 1120));
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

  static Future<Uint8List> _x25519Public(Uint8List sk) => _x25519PublicWith(_x25519, sk);

  static Future<Uint8List> _x25519Shared(Uint8List sk, Uint8List pk) async {
    try {
      return await _x25519SharedWith(_x25519, sk, pk);
    } on SsbCryptoException {
      rethrow;
    } catch (_) {
      // A platform backend (CryptoKit) may reject a degenerate peer point
      // that the Dart code would silently accept; either way the caller
      // gets the package's one typed error, never a PlatformException.
      throw const SsbCryptoException('bad x25519 input');
    }
  }

  static Future<Uint8List> _x25519PublicWith(X25519 impl, Uint8List sk) async {
    final kp = await impl.newKeyPairFromSeed(sk);
    return Uint8List.fromList((await kp.extractPublicKey()).bytes);
  }

  static Future<Uint8List> _x25519SharedWith(
      X25519 impl, Uint8List sk, Uint8List pk) async {
    final kp = await impl.newKeyPairFromSeed(sk);
    final s = await impl.sharedSecretKey(
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
