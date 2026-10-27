import 'dart:typed_data';

import 'bytes.dart';
import 'kdf.dart';

/// A single Shamir share, wire format v2 (SSB-2026-002, design D2).
///
///     version(1)=2 | threshold(1) | x(1) | epoch(2, u16be) | salt(8) | keyCheck(16) | y(secretLen)
///
/// For a 32-byte tier key that is [headerLength] + 32 = 61 bytes.
///
/// `keyCheck = HKDF-SHA384(ikm = secret, salt = salt, info = 'ssb/v2/share-check' || u16be(epoch))[0..16]`
/// lets the combiner verify the reconstruction (catches mismatched or
/// corrupted shares). The 8-byte [salt] is drawn once per [Shamir.split], so
/// two independent splits of the SAME secret carry different checks: a share
/// no longer reveals whether two kits were cut from one key (v1's unsalted
/// 64-bit tag did, red team B5), the tag is 128 bits, and the [epoch] it is
/// bound to cannot be rewritten without invalidating it.
///
/// Caveat (unchanged): keyCheck is a deterministic function of the secret
/// that is stored in every share, so a single share lets an attacker confirm
/// a guess of a LOW-ENTROPY secret offline. Shamir secrets MUST be uniformly
/// random (e.g. 256-bit keys); [Shamir.split] enforces
/// [Shamir.minSecretLength] bytes.
///
/// Version-1 shares (43 bytes, no epoch/salt, 8-byte check) are parsed only
/// by `ShareV1` in `package:ssb_crypto/legacy_v1.dart`; [Share.fromBytes]
/// refuses them.
class Share {
  static const version = 2;
  static const saltLength = 8;
  static const keyCheckLength = 16;

  /// Bytes before `y`: version, threshold, x, epoch(2), salt(8), keyCheck(16).
  static const headerLength = 3 + 2 + saltLength + keyCheckLength;

  /// Largest epoch the 2-byte field can carry.
  static const maxEpoch = 0xffff;

  final int threshold;
  final int x;

  /// Key generation this share belongs to (the tier epoch at split time).
  final int epoch;
  final Uint8List salt;
  final Uint8List keyCheck;
  final Uint8List y;

  Share(this.threshold, this.x, this.epoch, this.salt, this.keyCheck, this.y);

  Uint8List toBytes() =>
      concatBytes([[version, threshold, x], u16be(epoch), salt, keyCheck, y]);

  /// Parses a v2 share. Structural checks only: version byte 2, threshold
  /// >= 2, x != 0, at least one byte of y. Everything else is verified when
  /// the share is combined.
  factory Share.fromBytes(Uint8List b) {
    if (b.length < headerLength + 1 || b[0] != version || b[1] < 2 || b[2] == 0) {
      throw const SsbCryptoException('invalid share');
    }
    final epoch = (b[3] << 8) | b[4];
    return Share(
      b[1],
      b[2],
      epoch,
      Uint8List.fromList(b.sublist(5, 5 + saltLength)),
      Uint8List.fromList(b.sublist(5 + saltLength, headerLength)),
      Uint8List.fromList(b.sublist(headerLength)),
    );
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

  static const _checkInfo = 'ssb/v2/share-check';

  /// Splits [secret] into [shares] shares of which [threshold] reconstruct
  /// it, all stamped with [epoch] (0..[Share.maxEpoch]) and one fresh salt.
  static Future<List<Share>> split(Uint8List secret,
      {int shares = 3, int threshold = 2, required int epoch}) async {
    if (threshold < 2 || threshold > shares || shares > 255 ||
        secret.length < minSecretLength) {
      throw const SsbCryptoException('bad shamir parameters');
    }
    if (epoch < 0 || epoch > Share.maxEpoch) {
      throw const SsbCryptoException('bad epoch');
    }
    // Snapshot before the first await (see Aead.seal): a wipe of the
    // caller's buffer mid-flight must not produce consistent-looking shares
    // of a zero secret.
    final sec = Uint8List.fromList(secret);
    final salt = randomBytes(Share.saltLength);
    try {
      final check = await _keyCheck(sec, salt, epoch);
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
        for (var s = 0; s < shares; s++)
          Share(threshold, s + 1, epoch, Uint8List.fromList(salt),
              Uint8List.fromList(check), ys[s])
      ];
    } finally {
      wipe(sec);
    }
  }

  /// Reconstructs the secret from at least `threshold` distinct shares.
  ///
  /// Every share must agree on threshold, y length, epoch, salt and
  /// keyCheck (shares from another split -- a different key generation, or
  /// an independent split of the same key -- are refused before any
  /// arithmetic), indexes must be in 1..255 with no conflicting duplicates,
  /// and the reconstructed secret must reproduce the keyCheck.
  static Future<Uint8List> combine(List<Share> shares) async {
    if (shares.isEmpty) throw const SsbCryptoException('not enough shares');
    final first = shares.first;
    final k = first.threshold;
    final len = first.y.length;
    if (first.salt.length != Share.saltLength ||
        first.keyCheck.length != Share.keyCheckLength ||
        first.epoch < 0 || first.epoch > Share.maxEpoch) {
      throw const SsbCryptoException('invalid share');
    }
    // Snapshot the key check: it is compared after the final await (see
    // Aead.seal). Everything else is consumed before the first await.
    final expectedCheck = Uint8List.fromList(first.keyCheck);
    // Dedupe by share index (first occurrence wins; a repeated index with
    // different data is a conflict), then require k DISTINCT shares.
    final byX = <int, Share>{};
    for (final s in shares) {
      if (s.threshold != k || s.y.length != len || s.x < 1 || s.x > 255 ||
          s.epoch != first.epoch ||
          !constantTimeEquals(s.salt, first.salt) ||
          !constantTimeEquals(s.keyCheck, first.keyCheck)) {
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
    if (!constantTimeEquals(
        await _keyCheck(out, first.salt, first.epoch), expectedCheck)) {
      wipe(out);
      throw const SsbCryptoException('shares do not match');
    }
    return out;
  }

  static Future<Uint8List> _keyCheck(Uint8List secret, Uint8List salt, int epoch) =>
      hkdfSha384Bytes(
          ikm: secret,
          salt: salt,
          info: concatBytes([utf8Bytes(_checkInfo), u16be(epoch)]),
          length: Share.keyCheckLength);

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
