import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

/// Web build: no FFI, so the pure-Dart implementations are used. Verified
/// against the C implementations and against X-Wing's official vectors.
abstract final class MlKem768 {
  static (Uint8List pk, Uint8List sk) keyGen(Uint8List coins) =>
      PqcKem.kyber768.generateKeyPair(coins);

  static (Uint8List ct, Uint8List ss) encaps(Uint8List pk, Uint8List coins) =>
      PqcKem.kyber768.encapsulate(pk, coins);

  static Uint8List decaps(Uint8List ct, Uint8List sk) =>
      PqcKem.kyber768.decapsulate(sk, ct);
}

abstract final class MlDsa65 {
  static final _params = DilithiumParams.get(DilithiumParameter.mlDsa65);

  static (Uint8List pk, Uint8List sk) keyGen(Uint8List seed32) =>
      MlDsa.generateKeyPairSeeded(_params, seed32);

  static Uint8List sign(Uint8List sk, Uint8List message) =>
      MlDsa.sign(sk, message, _params);

  static bool verify(Uint8List pk, Uint8List message, Uint8List signature) =>
      MlDsa.verify(pk, message, signature, _params);
}
