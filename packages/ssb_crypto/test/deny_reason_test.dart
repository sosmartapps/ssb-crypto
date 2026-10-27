import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  late XWingKeyPair kp, other;
  setUpAll(() async {
    kp = await XWing.generateKeyPair();
    other = await XWing.generateKeyPair();
  });

  Future<Uint8List> seal(String reason, {String id = 'req1'}) =>
      DenyReason.seal(recipientPublicKey: kp.publicKey, requestId: id, reason: reason);

  test('round trip, including non-ASCII', () async {
    for (final s in ['no', 'That was not me. Please call me first.', 'Nein, ich habe das nicht veranlasst — üé \u{1F512}']) {
      final b = await seal(s);
      expect(b[0], DenyReason.version);
      expect(await DenyReason.open(recipientSecretKey: kp.secretKey, requestId: 'req1', sealed: b), s);
    }
  });

  test('the blob contains no plaintext and hides exact length', () async {
    const s = 'my secret words about why';
    final a = await seal(s);
    final b = await seal('x');
    expect(String.fromCharCodes(a).contains(s), isFalse);
    expect(a.length, b.length, reason: 'same size bucket');
    final c = await seal('y' * 400);
    expect(c.length, greaterThan(a.length));
  });

  test('only the requester key opens it', () async {
    final b = await seal('private');
    expect(
        () => DenyReason.open(recipientSecretKey: other.secretKey, requestId: 'req1', sealed: b),
        throwsA(isA<SsbCryptoException>()));
  });

  test('bound to the request id', () async {
    final b = await seal('private');
    expect(
        () => DenyReason.open(recipientSecretKey: kp.secretKey, requestId: 'req2', sealed: b),
        throwsA(isA<SsbCryptoException>()));
  });

  test('tamper, truncation and unknown version are refused', () async {
    final b = await seal('private');
    final t = Uint8List.fromList(b)..[b.length - 1] ^= 1;
    final v = Uint8List.fromList(b)..[0] = 2;
    for (final bad in [t, v, Uint8List(0), Uint8List.sublistView(b, 0, 40)]) {
      expect(
          () => DenyReason.open(recipientSecretKey: kp.secretKey, requestId: 'req1', sealed: bad),
          throwsA(isA<SsbCryptoException>()));
    }
  });

  test('refuses empty, oversize, and bad recipient key', () async {
    expect(() => seal(''), throwsA(isA<SsbCryptoException>()));
    expect(() => seal('a' * 501), throwsA(isA<SsbCryptoException>()));
    expect(
        () => DenyReason.seal(
            recipientPublicKey: Uint8List(XWing.publicKeyLength), requestId: 'r', reason: 'x'),
        throwsA(isA<SsbCryptoException>()));
    expect((await seal('a' * 500)).isNotEmpty, isTrue);
  });
}
