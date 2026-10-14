import 'dart:math';
import 'dart:typed_data';

class MLKEMException implements Exception {}

class MLKEMKeyPairGenerationException implements MLKEMException {
  final int cError;

  MLKEMKeyPairGenerationException(this.cError);
}

class MLKEMCoinsWrongSize implements MLKEMException {}

class MLKEMPublicKeyWrongLengthException implements MLKEMException {}

class MLKEMSecretKeyWrongLengthException implements MLKEMException {}

class MLKEMCiphertextWrongLengthException implements MLKEMException {}

class MLKEMEncapsulationFailedException implements MLKEMException {
  final int cError;

  MLKEMEncapsulationFailedException(this.cError);
}

class MLKEMDecapsulationFailedException implements MLKEMException {
  final int cError;

  MLKEMDecapsulationFailedException(this.cError);
}

class KeyPair {
  final Uint8List secretKey;
  final Uint8List publicKey;

  KeyPair({required this.secretKey, required this.publicKey});
}

class EncapsulationResult {
  final Uint8List ciphertext;
  final Uint8List sharedSecret;

  EncapsulationResult({required this.ciphertext, required this.sharedSecret});
}

Uint8List getRandomCoins() {
  final random = Random.secure();
  final coins = List.generate(32, (_) => random.nextInt(256));
  return Uint8List.fromList(coins);
}
