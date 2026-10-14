import 'dart:typed_data';

import 'package:mldsa_native/mldsa65.dart';
import 'package:mlkem_native/mlkem768.dart';

/// ML-KEM-768 (FIPS 203) via the vendored mlkem-native C code.
abstract final class MlKem768 {
  static final _impl = MLKEM768();

  /// [coins] is d||z (64 bytes), per FIPS 203.
  static (Uint8List pk, Uint8List sk) keyGen(Uint8List coins) {
    final kp = _impl.generateKeyPair(coins: coins);
    return (kp.publicKey, kp.secretKey);
  }

  /// [coins] is m (32 bytes).
  static (Uint8List ct, Uint8List ss) encaps(Uint8List pk, Uint8List coins) {
    final r = _impl.encapsulate(pk, coins: coins);
    return (r.ciphertext, r.sharedSecret);
  }

  static Uint8List decaps(Uint8List ct, Uint8List sk) => _impl.decapsulate(ct, sk);
}

/// ML-DSA-65 (FIPS 204) via the vendored mldsa-native C code.
abstract final class MlDsa65 {
  static final _impl = MLDSA65();

  static (Uint8List pk, Uint8List sk) keyGen(Uint8List seed32) {
    final kp = _impl.generateKeyPair(coins: seed32);
    return (kp.publicKey, kp.secretKey);
  }

  static Uint8List sign(Uint8List sk, Uint8List message) => _impl.sign(sk, message);

  static bool verify(Uint8List pk, Uint8List message, Uint8List signature) =>
      _impl.verify(pk, message, signature);
}
