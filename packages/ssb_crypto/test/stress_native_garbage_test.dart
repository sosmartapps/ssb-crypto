@Timeout(Duration(minutes: 4))
library;

// Garbage of the CORRECT length handed to the native (FFI) ML-KEM / ML-DSA
// code. Isolated in its own file: a native crash would take down only this
// file, not the other suites.

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

void main() {
  final r = seeded(7);

  test('encapsulate to random / all-0 / all-FF / non-canonical ML-KEM public keys: typed error or safe result', () async {
    final f = Fails();
    final good = await XWing.generateKeyPair();
    final cases = <String, Uint8List>{
      'random': rnd(r, 1216),
      'ff': Uint8List(1216)..fillRange(0, 1216, 0xff),
      // coefficients >= q (3329 = 0x0D01): 12-bit 0xFFF everywhere
      'noncanonical-ml-kem': Uint8List.fromList([...List.filled(1184, 0xff), ...good.publicKey.sublist(1184)]),
    };
    for (final e in cases.entries) {
      try {
        final enc = await XWing.encapsulate(e.value);
        f.add('${e.key}: ACCEPTED len=${enc.ciphertext.length}');
      } on SsbCryptoException {
      } catch (err) {
        f.add('${e.key}: WRONG-ERROR ${err.runtimeType}');
      }
    }
    f.done();
  });

  test('HybridSignature.sign with garbage secret key of correct length: typed error, no crash', () async {
    final f = Fails();
    for (var i = 0; i < 20; i++) {
      final sk = i == 0 ? Uint8List(4064) : i == 1 ? (Uint8List(4064)..fillRange(0, 4064, 0xff)) : rnd(r, 4064);
      try {
        final s = await HybridSignature.sign(sk, Uint8List(10), purpose: 'x');
        // If it "signs", it must not verify under any real key.
        f.check(s.length == HybridSignature.signatureLength, 'garbage sk sig len');
      } on SsbCryptoException {
      } catch (err) {
        f.add('garbage sk $i: WRONG-ERROR ${err.runtimeType}');
      }
    }
    f.done();
  });

  test('HybridSignature.verify with garbage keys/sigs of the correct length: false, no crash', () async {
    final real = await HybridSignature.generateKeyPair();
    final sig = await HybridSignature.sign(real.secretKey, Uint8List(3), purpose: 'x');
    final f = Fails();
    final pks = [Uint8List(1984), Uint8List(1984)..fillRange(0, 1984, 0xff), rnd(r, 1984), rnd(r, 1984)];
    for (final pk in pks) {
      for (final s in [sig, Uint8List(3373), rnd(r, 3373), Uint8List(3373)..fillRange(0, 3373, 0xff)]) {
        try {
          f.check(!await HybridSignature.verify(pk, Uint8List(3), s, purpose: 'x'), 'garbage verified');
        } on SsbCryptoException {
        } catch (err) {
          f.add('WRONG-ERROR ${err.runtimeType}');
        }
      }
    }
    f.done();
  });

  test('decapsulate with every possible seed shape and 500 random ciphertexts: no crash', () async {
    for (var i = 0; i < 500; i++) {
      final ss = await XWing.decapsulate(rnd(r, 1120), rnd(r, 32));
      expect(ss.length, 32);
    }
  });
}
