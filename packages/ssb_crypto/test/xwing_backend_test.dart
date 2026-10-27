import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartX25519;
import 'package:cryptography/helpers.dart' show DelegatingKeyExchangeAlgorithm;
import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

/// An X25519 that is right on the RFC 7748 keys but wrong on everything else,
/// to prove the install gate also cross-checks random keys.
class _WrongOnRandomKeys extends DelegatingKeyExchangeAlgorithm implements X25519 {
  @override
  final X25519 fallback = const DartX25519();
  int calls = 0;

  @override
  KeyPairType get keyPairType => fallback.keyPairType;

  @override
  Future<SimpleKeyPair> newKeyPair() => fallback.newKeyPair();

  @override
  Future<SimpleKeyPair> newKeyPairFromSeed(List<int> seed) =>
      fallback.newKeyPairFromSeed(seed);

  @override
  Future<SecretKey> sharedSecretKey(
      {required KeyPair keyPair, required PublicKey remotePublicKey}) async {
    final s = await fallback.sharedSecretKey(
        keyPair: keyPair, remotePublicKey: remotePublicKey);
    final b = await s.extractBytes();
    // First 4 calls are the RFC 7748 checks; corrupt everything after.
    if (++calls > 4) b[0] ^= 1;
    return SecretKey(b);
  }
}

class _AlwaysWrong extends _WrongOnRandomKeys {
  @override
  Future<SecretKey> sharedSecretKey(
      {required KeyPair keyPair, required PublicKey remotePublicKey}) async {
    final b = await (await fallback.sharedSecretKey(
            keyPair: keyPair, remotePublicKey: remotePublicKey))
        .extractBytes();
    b[31] ^= 0x80;
    return SecretKey(b);
  }
}

class _Throws extends _WrongOnRandomKeys {
  @override
  Future<SecretKey> sharedSecretKey(
          {required KeyPair keyPair, required PublicKey remotePublicKey}) =>
      throw StateError('platform channel exploded');
}

Future<void> _vectorsPass() async {
  final vectors = (jsonDecode(File('test/vectors/xwing.json').readAsStringSync()) as List)
      .cast<Map<String, dynamic>>();
  for (final v in vectors) {
    final kp = await XWing.generateKeyPairDerand(hexDecode(v['seed']));
    expect(hexEncode(kp.publicKey), v['pk']);
    final enc = await XWing.encapsulateDerand(kp.publicKey, hexDecode(v['eseed']));
    expect(hexEncode(enc.ciphertext), v['ct']);
    expect(hexEncode(enc.sharedSecret), v['ss']);
    expect(hexEncode(await XWing.decapsulate(hexDecode(v['ct']), kp.secretKey)), v['ss']);
  }
}

void main() {
  tearDown(XWing.resetX25519);

  test('a correct backend installs and every X-Wing vector still passes', () async {
    expect(await XWing.installX25519(const DartX25519(), name: 'Dart (explicit)'), isTrue);
    expect(XWing.x25519Backend, 'Dart (explicit)');
    await _vectorsPass();
  });

  test('a backend wrong only on random keys is rejected (cross-check)', () async {
    final before = XWing.x25519Backend;
    expect(await XWing.installX25519(_WrongOnRandomKeys(), name: 'bad'), isFalse);
    expect(XWing.x25519Backend, before);
    await _vectorsPass();
  });

  test('a backend wrong on the RFC 7748 vector is rejected', () async {
    expect(await XWing.installX25519(_AlwaysWrong(), name: 'bad'), isFalse);
    await _vectorsPass();
  });

  test('a backend that throws is rejected, not installed', () async {
    expect(await XWing.installX25519(_Throws(), name: 'bad'), isFalse);
    await _vectorsPass();
  });

  test('crossChecks: 0 still enforces RFC 7748', () async {
    expect(await XWing.installX25519(_AlwaysWrong(), name: 'bad', crossChecks: 0), isFalse);
  });
}
