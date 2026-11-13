import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

// Reported by ATOSAN (2026-10-27): HMAC zero-pads a short key, so shared
// secrets that differ only in trailing zeros gave identical key schedules.
// Not reachable through the KEM (always 32 bytes); refused anyway.
void main() {
  Future<HpkeKeySchedule> ks(List<int> ss) => Hpke.keySchedule(ss, const [1, 2, 3],
      kemId: Hpke.kemXWing, kdfId: Hpke.kdfHkdfSha256, aeadId: Hpke.aeadAes256Gcm);

  test('shared secrets of any length other than 32 are refused', () async {
    for (final n in [0, 1, 4, 31, 33, 64]) {
      await expectLater(ks(Uint8List(n)..fillRange(0, n, 1)), throwsA(isA<SsbCryptoException>()),
          reason: 'length $n');
    }
  });

  test('two different 32-byte secrets still give different schedules', () async {
    final a = await ks(Uint8List(32)..[0] = 1);
    final b = await ks(Uint8List(32)..[0] = 2);
    expect(a.key, isNot(b.key));
    a.erase();
    b.erase();
  });
}
