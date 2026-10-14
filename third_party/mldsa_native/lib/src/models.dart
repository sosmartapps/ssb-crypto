import 'dart:ffi' as ffi;
import 'dart:math';
import 'dart:typed_data';

class InternalParameters {
  final int publicKeyBytes;
  final int secretKeyBytes;
  final int signatureBytes;

  final int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Uint8>,
  )
  keypairDerand;
  final int Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>) keypair;

  int Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Size>,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
  )
  sign;

  int Function(
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
    int,
    ffi.Pointer<ffi.Uint8>,
  )
  verify;

  InternalParameters({
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.keypair,
    required this.keypairDerand,
    required this.signatureBytes,
    required this.sign,
    required this.verify,
  });
}

class MLDSAException implements Exception {}

class MLDSAKeyPairGenerationException implements MLDSAException {
  final int cError;

  MLDSAKeyPairGenerationException(this.cError);
}

class KeyPair {
  final Uint8List secretKey;
  final Uint8List publicKey;

  KeyPair({required this.secretKey, required this.publicKey});
}

class MLDSACoinsWrongSize extends MLDSAException {}

/// SSB PATCH 3: a key, context or other buffer had the wrong length for this
/// parameter set. Thrown BEFORE any native memory is touched.
class MLDSAWrongLengthException extends MLDSAException {
  /// Which argument was wrong ("private key", "public key", ...).
  final String what;
  final int expected;
  final int actual;

  MLDSAWrongLengthException(this.what, {required this.expected, required this.actual});

  @override
  String toString() =>
      'MLDSAWrongLengthException: $what must be $expected bytes, got $actual';
}

Uint8List getRandomCoins() {
  final random = Random.secure();
  final coins = List.generate(32, (_) => random.nextInt(256));
  return Uint8List.fromList(coins);
}
