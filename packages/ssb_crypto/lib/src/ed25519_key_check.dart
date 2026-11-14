/// Validity check for an Ed25519 public key that came from outside.
///
/// WHY. The Ed25519 verifier in package:cryptography checks the signature
/// encoding but not the public key: it accepts a key A of small order (the
/// identity, or a point of order 2, 4 or 8) or one with a torsion component.
/// For the identity point the pair (R = [k]B, S = k) verifies for ANY message,
/// so anyone can forge the Ed25519 half of a signature with no secret at all
/// (report by hrydarie, 2026-11-03). Keys we generate are scalar multiples of
/// the base point, so they are always in the prime-order subgroup and are
/// never affected; the gap only opens for a key supplied from outside.
///
/// A key passes only if it is a canonical encoding of a curve point, is not
/// the identity, and has order exactly L ([L]A is the identity). Not constant
/// time: public keys are not secret.
abstract final class Ed25519KeyCheck {
  static final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
  static final BigInt _l = (BigInt.one << 252) +
      BigInt.parse('27742317777372353535851937790883648493');
  static final BigInt _d =
      (BigInt.from(-121665) * BigInt.from(121666).modInverse(_p)) % _p;
  static final BigInt _d2 = (_d * BigInt.two) % _p;
  static final BigInt _sqrtM1 =
      BigInt.two.modPow((_p - BigInt.one) ~/ BigInt.from(4), _p);

  /// True only for a 32-byte canonical encoding of a prime-order, non-identity
  /// Ed25519 point.
  static bool isValidPublicKey(List<int> encoded) {
    if (encoded.length != 32) return false;
    var y = BigInt.zero;
    for (var i = 31; i >= 0; i--) {
      y = (y << 8) | BigInt.from(encoded[i]);
    }
    final sign = (y >> 255).toInt();
    y &= (BigInt.one << 255) - BigInt.one;
    if (y >= _p) return false; // non-canonical field element

    // Recover x from the curve equation  -x^2 + y^2 = 1 + d x^2 y^2.
    final y2 = (y * y) % _p;
    final num = (y2 - BigInt.one) % _p;
    final den = (_d * y2 + BigInt.one) % _p;
    final x2 = (num * den.modInverse(_p)) % _p;
    var x = x2.modPow((_p + BigInt.from(3)) ~/ BigInt.from(8), _p);
    if ((x * x - x2) % _p != BigInt.zero) x = (x * _sqrtM1) % _p;
    if ((x * x - x2) % _p != BigInt.zero) return false; // not on the curve
    // x = 0 is the identity (y = 1) or the order-2 point (y = -1); both are
    // small-order, and x = 0 with the sign bit set is not a canonical encoding.
    if (x == BigInt.zero) return false;
    if (x.isOdd != (sign == 1)) x = _p - x;

    // Prime-order test: [L]A must be the identity.
    final a = _Pt(x, y, BigInt.one, (x * y) % _p);
    var r = _Pt(BigInt.zero, BigInt.one, BigInt.one, BigInt.zero);
    for (var i = _l.bitLength - 1; i >= 0; i--) {
      r = _add(r, r);
      if (((_l >> i) & BigInt.one) == BigInt.one) r = _add(r, a);
    }
    return r.x == BigInt.zero && r.y == r.z;
  }

  // Unified addition on the twisted Edwards curve (a = -1), extended
  // coordinates (add-2008-hwcd-3); complete for Ed25519.
  static _Pt _add(_Pt p1, _Pt p2) {
    final a = ((p1.y - p1.x) * (p2.y - p2.x)) % _p;
    final b = ((p1.y + p1.x) * (p2.y + p2.x)) % _p;
    final c = (p1.t * _d2 * p2.t) % _p;
    final dd = (p1.z * BigInt.two * p2.z) % _p;
    final e = b - a, f = dd - c, g = dd + c, h = b + a;
    return _Pt((e * f) % _p, (g * h) % _p, (f * g) % _p, (e * h) % _p);
  }
}

class _Pt {
  final BigInt x, y, z, t;
  _Pt(this.x, this.y, this.z, this.t);
}
