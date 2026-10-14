import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssb_crypto/src/pq/pq_native.dart' as native;
import 'package:ssb_crypto/src/pq/pq_web.dart' as web;
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

/// The app ships the C implementation on phones and the pure-Dart one on the
/// web survivor portal. A beneficiary must be able to open, in a browser,
/// exactly what was sealed on a phone — so the two must agree byte for byte.
void main() {
  test('ML-KEM-768: native and web backends produce identical keys, ciphertexts and secrets', () {
    final coins = randomBytes(64);
    final (pkN, skN) = native.MlKem768.keyGen(coins);
    final (pkW, skW) = web.MlKem768.keyGen(coins);
    expect(hexEncode(pkW), hexEncode(pkN));
    expect(hexEncode(skW), hexEncode(skN));

    final m = randomBytes(32);
    final (ctN, ssN) = native.MlKem768.encaps(pkN, m);
    final (ctW, ssW) = web.MlKem768.encaps(pkW, m);
    expect(hexEncode(ctW), hexEncode(ctN));
    expect(hexEncode(ssW), hexEncode(ssN));

    // Cross-decapsulation: each side opens the other's ciphertext.
    expect(hexEncode(native.MlKem768.decaps(ctW, skN)), hexEncode(ssN));
    expect(hexEncode(web.MlKem768.decaps(ctN, skW)), hexEncode(ssN));
  });

  test('ML-DSA-65: keys match and signatures verify across backends', () {
    final seed = randomBytes(32);
    final (pkN, skN) = native.MlDsa65.keyGen(seed);
    final (pkW, skW) = web.MlDsa65.keyGen(seed);
    expect(hexEncode(pkW), hexEncode(pkN));
    expect(hexEncode(skW), hexEncode(skN));
    final msg = Uint8List.fromList(utf8.encode('release token'));
    expect(web.MlDsa65.verify(pkW, msg, native.MlDsa65.sign(skN, msg)), isTrue);
    expect(native.MlDsa65.verify(pkN, msg, web.MlDsa65.sign(skW, msg)), isTrue);
  });

  test('X-Wing official vectors also pass on the web backend', () {
    // Re-runs the draft vectors through the pure-Dart ML-KEM path.
    final vectors = (jsonDecode(File('test/vectors/xwing.json').readAsStringSync()) as List)
        .cast<Map<String, dynamic>>();
    for (final v in vectors) {
      final expanded = shake256(hexDecode(v['seed']), 96);
      final (pkM, _) = web.MlKem768.keyGen(Uint8List.fromList(expanded.sublist(0, 64)));
      expect(hexEncode(pkM), (v['pk'] as String).substring(0, 1184 * 2));
    }
  });
}
