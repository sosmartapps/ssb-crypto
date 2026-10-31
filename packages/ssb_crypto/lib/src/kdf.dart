import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// HKDF-SHA-384 (RFC 5869) for all SSB key derivations (spec §6.2).
Future<Uint8List> hkdfSha384({
  required List<int> ikm,
  required List<int> salt,
  required String info,
  int length = 32,
}) =>
    hkdfSha384Bytes(ikm: ikm, salt: salt, info: utf8Bytes(info), length: length);

/// [hkdfSha384] with a binary `info` (for contexts that carry fixed-width
/// integers, e.g. the v2 Shamir key check: `'ssb/v2/share-check' || u16(epoch)`).
Future<Uint8List> hkdfSha384Bytes({
  required List<int> ikm,
  required List<int> salt,
  required List<int> info,
  int length = 32,
}) async {
  // package:cryptography reads SecretKeyData lazily, after an await, so the
  // input keying material is copied here before anything can wipe it.
  final k0 = Uint8List.fromList(ikm);
  final s0 = Uint8List.fromList(salt);
  final i0 = Uint8List.fromList(info);
  try {
    final k = await Hkdf(hmac: Hmac.sha384(), outputLength: length).deriveKey(
      secretKey: SecretKeyData(k0),
      nonce: s0,
      info: i0,
    );
    return Uint8List.fromList(await k.extractBytes());
  } finally {
    wipe(k0);
  }
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

  /// Tighter ceilings enforced by [validateForUnlock] (stored params are
  /// attacker-influenced). 512 MiB, t<=8, p<=4.
  static const unlockMaxMemoryKiB = 512 * 1024;
  static const unlockMaxIterations = 8;
  static const unlockMaxParallelism = 4;

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
    // Ceiling for UNLOCK: these parameters are stored beside the vault, so a
    // hostile or compromised server could otherwise hand a phone or browser
    // tab 1 GiB x t=32 x p=16 and OOM or hang it (audit 2026-10-31). Four
    // times production is far above anything calibration picks.
    if (memoryKiB > unlockMaxMemoryKiB || iterations > unlockMaxIterations ||
        parallelism > unlockMaxParallelism) {
      throw const SsbCryptoException('argon2 parameters above maximum');
    }
    if (memoryKiB < minimum.memoryKiB || iterations < minimum.iterations ||
        parallelism < minimum.parallelism) {
      throw const SsbCryptoException('argon2 parameters below minimum');
    }
  }
}

Future<Uint8List> argon2id(
    List<int> password, List<int> salt, Argon2Params p) async {
  p.validate();
  // package:cryptography reads SecretKeyData lazily, after an await, so the
  // password and salt are copied here before anything can wipe the caller's
  // buffers (same pattern as hkdfSha384Bytes; SSB-2026-001 residual).
  final pw0 = Uint8List.fromList(password);
  final salt0 = Uint8List.fromList(salt);
  try {
    final k = await Argon2id(
      memory: p.memoryKiB,
      iterations: p.iterations,
      parallelism: p.parallelism,
      hashLength: 32,
    ).deriveKey(secretKey: SecretKeyData(pw0), nonce: salt0);
    return Uint8List.fromList(await k.extractBytes());
  } finally {
    wipe(pw0);
  }
}
