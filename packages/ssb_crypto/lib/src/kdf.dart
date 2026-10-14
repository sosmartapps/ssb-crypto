import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// HKDF-SHA-384 (RFC 5869) for all SSB key derivations (spec §6.2).
Future<Uint8List> hkdfSha384({
  required List<int> ikm,
  required List<int> salt,
  required String info,
  int length = 32,
}) async {
  final k = await Hkdf(hmac: Hmac.sha384(), outputLength: length).deriveKey(
    secretKey: SecretKeyData(ikm),
    nonce: salt,
    info: utf8Bytes(info),
  );
  return Uint8List.fromList(await k.extractBytes());
}

/// Argon2id parameters (RFC 9106). Stored alongside the vault so they can be
/// raised later without breaking existing vaults.
class Argon2Params {
  final int memoryKiB;
  final int iterations;
  final int parallelism;
  const Argon2Params({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  }) : _allowBelowMinimum = false;

  /// Parameters that are exempt from the [minimum] floor. Tests and the
  /// debug-only fast-KDF mode ONLY; never serialized as such: [fromJson]
  /// never produces one unless the caller opts in with `allowTestOnly`.
  const Argon2Params.testing({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  }) : _allowBelowMinimum = true;

  final bool _allowBelowMinimum;

  /// Sanity ceilings so attacker-influenced parameters cannot request an
  /// absurd amount of memory/time.
  static const maxMemoryKiB = 1 << 20; // 1 GiB
  static const maxIterations = 32;
  static const maxParallelism = 16;

  /// Production default: 128 MiB, t=3, p=1 (calibrated per device at setup,
  /// never below [minimum]).
  static const production =
      Argon2Params(memoryKiB: 128 * 1024, iterations: 3, parallelism: 1);

  /// Floor for low-memory devices.
  static const minimum =
      Argon2Params(memoryKiB: 64 * 1024, iterations: 3, parallelism: 1);

  /// Unit tests only. Never used by the app.
  static const testOnly =
      Argon2Params.testing(memoryKiB: 1024, iterations: 1, parallelism: 1);

  Map<String, int> toJson() =>
      {'m': memoryKiB, 't': iterations, 'p': parallelism};

  /// Parses stored parameters. Any missing / non-integer / out-of-range
  /// field is an [SsbCryptoException] (never a raw cast error). The
  /// [minimum] floor is enforced where the parameters are USED
  /// ([Unlock.deriveUnlockKey]). Pass [allowTestOnly] (debug builds only) to
  /// accept the exact [testOnly] values.
  factory Argon2Params.fromJson(Map<String, dynamic> j, {bool allowTestOnly = false}) {
    final m = j['m'], t = j['t'], p = j['p'];
    if (m is! int || t is! int || p is! int) {
      throw const SsbCryptoException('bad argon2 parameters');
    }
    final parsed = Argon2Params(memoryKiB: m, iterations: t, parallelism: p);
    parsed.validate();
    if (allowTestOnly &&
        m == testOnly.memoryKiB &&
        t == testOnly.iterations &&
        p == testOnly.parallelism) {
      return testOnly;
    }
    return parsed;
  }

  /// Throws [SsbCryptoException] unless the values are sane (positive and
  /// under the ceilings; Argon2 also needs memory >= 8 * parallelism).
  void validate() {
    if (memoryKiB < 8 || iterations < 1 || parallelism < 1 ||
        memoryKiB > maxMemoryKiB || iterations > maxIterations ||
        parallelism > maxParallelism || memoryKiB < 8 * parallelism) {
      throw const SsbCryptoException('bad argon2 parameters');
    }
  }

  /// [validate] plus the downgrade floor: refuses anything weaker than
  /// [minimum] (memory, iterations) unless built with [Argon2Params.testing].
  void validateForUnlock() {
    validate();
    if (_allowBelowMinimum) return;
    if (memoryKiB < minimum.memoryKiB || iterations < minimum.iterations ||
        parallelism < minimum.parallelism) {
      throw const SsbCryptoException('argon2 parameters below minimum');
    }
  }
}

Future<Uint8List> argon2id(
    List<int> password, List<int> salt, Argon2Params p) async {
  p.validate();
  final k = await Argon2id(
    memory: p.memoryKiB,
    iterations: p.iterations,
    parallelism: p.parallelism,
    hashLength: 32,
  ).deriveKey(secretKey: SecretKeyData(password), nonce: salt);
  return Uint8List.fromList(await k.extractBytes());
}
