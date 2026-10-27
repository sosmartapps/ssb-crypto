import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

/// A signature produced by the SERVER (Node, @noble/post-quantum ML-DSA-65 +
/// node:crypto Ed25519) must verify under the
/// Dart client's HybridSignature (vendored mldsa-native). Fixture produced by the
/// server-side test harness (throwaway key).
void main() {
  final f = jsonDecode(File('test/fixtures_server_hybrid.json').readAsStringSync())
      as Map<String, dynamic>;
  final pk = hexDecode(f['publicKeyHex'] as String);
  final msg = hexDecode(f['messageHex'] as String);
  final sig = hexDecode(f['signatureHex'] as String);
  final purpose = f['purpose'] as String;

  test('server hybrid signature verifies in the Dart client (both legs)', () async {
    expect(await HybridSignature.verify(pk, msg, sig, purpose: purpose), isTrue);
  });

  test('and fails when either leg or the message is touched', () async {
    final a = Uint8List.fromList(sig)..[3] ^= 1;
    final b = Uint8List.fromList(sig)..[64 + 100] ^= 1;
    expect(await HybridSignature.verify(pk, msg, a, purpose: purpose), isFalse);
    expect(await HybridSignature.verify(pk, msg, b, purpose: purpose), isFalse);
    expect(await HybridSignature.verify(pk, Uint8List.fromList([...msg, 0]), sig, purpose: purpose),
        isFalse);
    expect(await HybridSignature.verify(pk, msg, sig, purpose: 'release-token'), isFalse);
  });
}
