// cn243 finding #4, sibling wrapper: mlkem_native already validated every
// key/ciphertext/coin length against what C reads (SSB_PATCHES.md ML-KEM
// patch 4 only moved the coin checks ahead of the native allocations). This
// pins that behavior for all three parameter sets.
import 'dart:typed_data';

import 'package:mlkem_native/mlkem1024.dart';
import 'package:mlkem_native/mlkem512.dart';
import 'package:mlkem_native/mlkem768.dart';
import 'package:mlkem_native/src/shared.dart' show MLKEM;
import 'package:test/test.dart';

void main() {
  final sets = <String, MLKEM Function()>{
    'ML-KEM-512': MLKEM512.new,
    'ML-KEM-768': MLKEM768.new,
    'ML-KEM-1024': MLKEM1024.new,
  };

  for (final e in sets.entries) {
    group(e.key, () {
      final impl = e.value();
      final kp = impl.generateKeyPair(coins: Uint8List(64));
      final enc = impl.encapsulate(kp.publicKey, coins: Uint8List(32));

      test('keygen coins must be exactly 64 bytes', () {
        for (final n in [0, 32, 63, 65]) {
          expect(() => impl.generateKeyPair(coins: Uint8List(n)),
              throwsA(isA<MLKEMCoinsWrongSize>()));
        }
      });

      test('encapsulate refuses wrong-size public key and coins', () {
        for (final n in [0, 1, kp.publicKey.length - 1, kp.publicKey.length + 1]) {
          expect(() => impl.encapsulate(Uint8List(n)),
              throwsA(isA<MLKEMPublicKeyWrongLengthException>()));
        }
        for (final n in [0, 31, 33, 64]) {
          expect(() => impl.encapsulate(kp.publicKey, coins: Uint8List(n)),
              throwsA(isA<MLKEMCoinsWrongSize>()));
        }
      });

      test('decapsulate refuses wrong-size ciphertext and secret key', () {
        expect(() => impl.decapsulate(Uint8List(1), kp.secretKey),
            throwsA(isA<MLKEMCiphertextWrongLengthException>()));
        expect(() => impl.decapsulate(enc.ciphertext, Uint8List(1)),
            throwsA(isA<MLKEMSecretKeyWrongLengthException>()));
        expect(() => impl.decapsulate(enc.ciphertext, Uint8List(kp.secretKey.length + 1)),
            throwsA(isA<MLKEMSecretKeyWrongLengthException>()));
      });

      test('round trip still works (control)', () {
        expect(impl.decapsulate(enc.ciphertext, kp.secretKey), enc.sharedSecret);
      });
    });
  }
}
