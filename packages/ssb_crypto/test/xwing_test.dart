import 'dart:convert';
import 'dart:io';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  final vectors = (jsonDecode(File('test/vectors/xwing.json').readAsStringSync()) as List)
      .cast<Map<String, dynamic>>();

  group('X-Wing draft-connolly-cfrg-xwing-kem-10 Appendix C vectors', () {
    for (var i = 0; i < vectors.length; i++) {
      final v = vectors[i];
      test('vector $i: keygen, encaps, decaps match', () async {
        final kp = await XWing.generateKeyPairDerand(hexDecode(v['seed']));
        expect(hexEncode(kp.secretKey), v['sk']);
        expect(hexEncode(kp.publicKey), v['pk']);
        final enc = await XWing.encapsulateDerand(kp.publicKey, hexDecode(v['eseed']));
        expect(hexEncode(enc.ciphertext), v['ct']);
        expect(hexEncode(enc.sharedSecret), v['ss']);
        final ss = await XWing.decapsulate(hexDecode(v['ct']), kp.secretKey);
        expect(hexEncode(ss), v['ss']);
      });
    }
  });

  test('random round trip', () async {
    final kp = await XWing.generateKeyPair();
    final enc = await XWing.encapsulate(kp.publicKey);
    expect(await XWing.decapsulate(enc.ciphertext, kp.secretKey), enc.sharedSecret);
  });

  test('wrong key yields a different secret (implicit rejection)', () async {
    final a = await XWing.generateKeyPair();
    final b = await XWing.generateKeyPair();
    final enc = await XWing.encapsulate(a.publicKey);
    expect(await XWing.decapsulate(enc.ciphertext, b.secretKey),
        isNot(equals(enc.sharedSecret)));
  });
}
