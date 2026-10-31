import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('unlock refuses attacker-sized Argon2 params (audit 2026-10-31)', () {
    for (final p in const [
      Argon2Params(memoryKiB: 1 << 20, iterations: 3, parallelism: 1),
      Argon2Params(memoryKiB: 128 * 1024, iterations: 32, parallelism: 1),
      Argon2Params(memoryKiB: 128 * 1024, iterations: 3, parallelism: 16),
    ]) {
      p.validate(); // still structurally valid...
      expect(p.validateForUnlock, throwsA(isA<SsbCryptoException>())); // ...but not for unlock
    }
    Argon2Params.production.validateForUnlock();
    Argon2Params.minimum.validateForUnlock();
    const Argon2Params(memoryKiB: 512 * 1024, iterations: 8, parallelism: 4).validateForUnlock();
  });
}
