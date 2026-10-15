import 'dart:typed_data';

import 'bytes.dart';
import 'kdf.dart';

/// A single Shamir share.
///
/// Wire format: version(1) | threshold(1) | x(1) | keyCheck(8) | y(secretLen)
/// keyCheck = HKDF(secret, "ssb/v1/share-check")[0..8] lets the combiner
/// verify the reconstruction (catches mismatched or corrupted shares).
///
/// Caveat: keyCheck is a deterministic 64-bit function of the secret that is
/// stored in every share. A single share therefore lets an attacker confirm
/// a guess of a LOW-ENTROPY secret offline. Shamir secrets MUST be uniformly
/// random (e.g. 256-bit keys); [Shamir.split] enforces
/// [Shamir.minSecretLength] bytes, and for a uniformly random secret the tag
/// leaks nothing practical beyond 64 bits of a hash.
class Share {
  static const version = 1;
  final int threshold;
  final int x;
  final Uint8List keyCheck;
  final Uint8List y;
  Share(this.threshold, this.x, this.keyCheck, this.y);

  Uint8List toBytes() =>
      concatBytes([[version, threshold, x], keyCheck, y]);

  factory Share.fromBytes(Uint8List b) {
    if (b.length < 3 + 8 + 1 || b[0] != version || b[1] < 2 || b[2] == 0) {
      throw const SsbCryptoException('invalid share');
    }
    return Share(b[1], b[2], Uint8List.fromList(b.sublist(3, 11)),
        Uint8List.fromList(b.sublist(11)));
  }

  /// Wipes the share's y-values (the secret-bearing part) in place.
  void erase() => wipe(y);
}

/// Shamir secret sharing over GF(2^8) (AES polynomial x^8+x^4+x^3+x+1).
///
/// The share polynomials are information-theoretically secure: fewer than
/// [threshold] share y-values reveal nothing about the secret, regardless of
/// computing power (quantum included). The per-share [Share.keyCheck] tag is
/// NOT part of that guarantee for low-entropy secrets (see [Share]), so the
/// secret must be uniformly random and at least [minSecretLength] bytes. Field
/// arithmetic uses branch-free multiply and exponentiation-based inverse (no
/// lookup tables), so timing does not depend on secret values.
abstract final class Shamir {
  /// Shortest secret [split] accepts. Secrets must be uniformly random keys.
  static const minSecretLength = 16;

  static Future<List<Share>> split(Uint8List secret,
      {int shares = 3, int threshold = 2}) async {
    if (threshold < 2 || threshold > shares || shares > 255 ||
        secret.length < minSecretLength) {
      throw const SsbCryptoException('bad shamir parameters');
    }
    // Snapshot before the first await (see Aead.seal): a wipe of the
    // caller's buffer mid-flight must not produce consistent-looking shares
    // of a zero secret.
    final sec = Uint8List.fromList(secret);
    try {
      final check = await _keyCheck(sec);
      final ys = List.generate(shares, (_) => Uint8List(sec.length));
      for (var i = 0; i < sec.length; i++) {
        // Fresh random coefficients per byte: f(x) = s + c1 x + ... + c(k-1) x^(k-1)
        final c = randomBytes(threshold - 1);
        for (var s = 0; s < shares; s++) {
          final x = s + 1;
          var acc = 0;
          for (var j = c.length - 1; j >= 0; j--) {
            acc = _mul(acc ^ c[j], x);
          }
          ys[s][i] = acc ^ sec[i];
        }
        wipe(c);
      }
      return [
        for (var s = 0; s < shares; s++) Share(threshold, s + 1, check, ys[s])
      ];
    } finally {
      wipe(sec);
    }
  }

  static Future<Uint8List> combine(List<Share> shares) async {
    if (shares.isEmpty) throw const SsbCryptoException('not enough shares');
    final k = shares.first.threshold;
    final len = shares.first.y.length;
    // Dedupe by share index (first occurrence wins; a repeated index with
    // different data is a conflict), then require k DISTINCT shares.
    final byX = <int, Share>{};
    for (final s in shares) {
      if (s.threshold != k || s.y.length != len || s.x < 1 || s.x > 255 ||
          !constantTimeEquals(s.keyCheck, shares.first.keyCheck)) {
        throw const SsbCryptoException('shares do not match');
      }
      final prev = byX[s.x];
      if (prev == null) {
        byX[s.x] = s;
      } else if (!constantTimeEquals(prev.y, s.y)) {
        throw const SsbCryptoException('shares do not match');
      }
    }
    if (byX.length < k) throw const SsbCryptoException('not enough shares');
    final use = byX.values.take(k).toList();
    final out = Uint8List(len);
    for (var i = 0; i < len; i++) {
      var acc = 0;
      for (var a = 0; a < k; a++) {
        // Lagrange basis at 0: prod_{b!=a} x_b / (x_b - x_a); minus == xor.
        var num = 1, den = 1;
        for (var b = 0; b < k; b++) {
          if (a == b) continue;
          num = _mul(num, use[b].x);
          den = _mul(den, use[b].x ^ use[a].x);
        }
        acc ^= _mul(use[a].y[i], _mul(num, _inv(den)));
      }
      out[i] = acc;
    }
    if (!constantTimeEquals(await _keyCheck(out), shares.first.keyCheck)) {
      wipe(out);
      throw const SsbCryptoException('shares do not match');
    }
    return out;
  }

  static Future<Uint8List> _keyCheck(Uint8List secret) async =>
      (await hkdfSha384(ikm: secret, salt: const [], info: 'ssb/v1/share-check', length: 8));

  /// Branch-free GF(2^8) multiply.
  static int _mul(int a, int b) {
    var p = 0;
    for (var i = 0; i < 8; i++) {
      p ^= a & -(b & 1);
      final hi = -((a >> 7) & 1);
      a = ((a << 1) ^ (0x1b & hi)) & 0xff;
      b >>= 1;
    }
    return p & 0xff;
  }

  /// a^254 = a^-1 in GF(2^8) (fixed sequence of multiplies).
  static int _inv(int a) {
    var r = 1, base = a;
    for (var e = 254; e > 0; e >>= 1) {
      if (e & 1 == 1) r = _mul(r, base);
      base = _mul(base, base);
    }
    return r;
  }
}
