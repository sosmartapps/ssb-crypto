// Regression for security review cn243 finding #4 (fixed by SSB_PATCHES.md
// ML-DSA patch 3): the vendored mldsa_native wrapper copied `publicKey` into
// a native buffer of publicKey.length bytes but told the C verifier it held a
// full public key (1952 bytes for ML-DSA-65): an over-read of caller-sized
// heap. ssb_crypto's HybridSignature checks lengths first, so this guards
// direct wrapper callers (defense in depth). A wrong-size public key must now
// throw a typed error; a wrong-size signature is simply invalid (false).
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
      final sig = impl.sign(kp.secretKey, msg);
      final pkLen = kp.publicKey.length;

      test('verify refuses a short / long / empty public key', () {
        for (final n in [0, 1, pkLen - 1, pkLen + 1, pkLen * 2]) {
          expect(() => impl.verify(Uint8List(n), msg, sig),
              throwsA(isA<MLDSAWrongLengthException>()),
              reason: 'public key of $n bytes');
        }
      });

      test('verify answers false for a wrong-size signature, never reads past it', () {
        for (final n in [0, 1, 5, sig.length - 1, sig.length + 1]) {
          expect(impl.verify(kp.publicKey, msg, Uint8List(n)), isFalse,
              reason: 'signature of $n bytes');
        }
      });

      test('verify refuses an over-long context', () {
        expect(() => impl.verify(kp.publicKey, msg, sig, context: Uint8List(256)),
            throwsA(isA<MLDSAWrongLengthException>()));
      });

      test('a correct-size key and signature still verify (control)', () {
        expect(impl.verify(kp.publicKey, msg, sig), isTrue);
        final bad = Uint8List.fromList(sig)..[0] ^= 1;
        expect(impl.verify(kp.publicKey, msg, bad), isFalse);
      });
    });
  }
}
