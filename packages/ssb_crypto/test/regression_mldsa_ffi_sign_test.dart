// Regression for security review cn243 finding #4 (fixed by SSB_PATCHES.md
// ML-DSA patch 3). Kept in its own file because, before the fix, it could
// crash the test process: MLDSAImpl.sign copied `privateKey` into a buffer of
// privateKey.length bytes, let C read secretKeyBytes (4032 for ML-DSA-65)
// from it, and the zeroization patch then wrote secretKeyBytes zeros over a
// buffer that may be far smaller (heap overflow). The wrapper must now throw
// a typed error before touching native memory.
import 'dart:typed_data';

import 'package:mldsa_native/mldsa44.dart';
import 'package:mldsa_native/mldsa65.dart';
import 'package:mldsa_native/mldsa87.dart';
import 'package:mldsa_native/src/models.dart';
import 'package:mldsa_native/src/shared.dart' show MLDSA;
import 'package:test/test.dart';

void main() {
  final sets = <String, MLDSA Function()>{
    'ML-DSA-44': MLDSA44.new,
    'ML-DSA-65': MLDSA65.new,
    'ML-DSA-87': MLDSA87.new,
  };
  final msg = Uint8List.fromList(List.generate(16, (i) => i));

  for (final e in sets.entries) {
    group(e.key, () {
      final impl = e.value();
      final kp = impl.generateKeyPair(coins: Uint8List(32));
      final skLen = kp.secretKey.length;

      test('sign refuses a short / long / empty secret key', () {
        for (final n in [0, 1, 32, skLen - 1, skLen + 1, skLen * 2]) {
          expect(() => impl.sign(Uint8List(n), msg),
              throwsA(isA<MLDSAWrongLengthException>()),
              reason: 'private key of $n bytes');
        }
      });

      test('the typed error is an MLDSAException and names the sizes', () {
        try {
          impl.sign(Uint8List(32), msg);
          fail('expected MLDSAWrongLengthException');
        } on MLDSAException catch (ex) {
          expect(ex, isA<MLDSAWrongLengthException>());
          final w = ex as MLDSAWrongLengthException;
          expect(w.expected, skLen);
          expect(w.actual, 32);
          expect(w.toString(), contains('private key'));
        }
      });

      test('sign refuses wrong-size coins and an over-long context', () {
        expect(() => impl.sign(kp.secretKey, msg, coins: Uint8List(31)),
            throwsA(isA<MLDSACoinsWrongSize>()));
        expect(() => impl.sign(kp.secretKey, msg, context: Uint8List(256)),
            throwsA(isA<MLDSAWrongLengthException>()));
      });

      test('generateKeyPair refuses wrong-size coins', () {
        expect(() => impl.generateKeyPair(coins: Uint8List(31)),
            throwsA(isA<MLDSACoinsWrongSize>()));
        expect(() => impl.generateKeyPair(coins: Uint8List(33)),
            throwsA(isA<MLDSACoinsWrongSize>()));
      });

      test('a correct-size key still signs and verifies (control)', () {
        final sig = impl.sign(kp.secretKey, msg);
        expect(impl.verify(kp.publicKey, msg, sig), isTrue);
        final ctx = Uint8List.fromList([1, 2, 3]);
        final sig2 = impl.sign(kp.secretKey, msg, context: ctx);
        expect(impl.verify(kp.publicKey, msg, sig2, context: ctx), isTrue);
        expect(impl.verify(kp.publicKey, msg, sig2), isFalse);
      });
    });
  }
}
