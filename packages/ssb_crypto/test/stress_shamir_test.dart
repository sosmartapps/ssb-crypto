@Timeout(Duration(minutes: 4))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

/// Independent reference GF(2^8), AES polynomial 0x11b.
int gmul(int a, int b) {
  var p = 0;
  while (b > 0) {
    if (b & 1 == 1) p ^= a;
    a <<= 1;
    if (a & 0x100 != 0) a ^= 0x11b;
    b >>= 1;
  }
  return p;
}

final _inv = () {
  final t = List<int>.filled(256, 0);
  for (var a = 1; a < 256; a++) {
    for (var b = 1; b < 256; b++) {
      if (gmul(a, b) == 1) t[a] = b;
    }
  }
  return t;
}();

/// Reference Lagrange interpolation at 0 for points (xs, ys).
int refInterp(List<int> xs, List<int> ys) {
  var acc = 0;
  for (var a = 0; a < xs.length; a++) {
    var num = 1, den = 1;
    for (var b = 0; b < xs.length; b++) {
      if (a == b) continue;
      num = gmul(num, xs[b]);
      den = gmul(den, xs[b] ^ xs[a]);
    }
    acc ^= gmul(ys[a], gmul(num, _inv[den]));
  }
  return acc;
}

void main() {
  final r = seeded(1);

  group('reference field sanity (test-local GF(256))', () {
    test('known vectors and axioms', () {
      expect(gmul(0x57, 0x83), 0xc1);
      expect(gmul(0x53, 0xca), 1);
      for (var a = 1; a < 256; a++) {
        expect(gmul(a, _inv[a]), 1);
      }
      for (var i = 0; i < 100000; i++) {
        final a = r.nextInt(256), b = r.nextInt(256), c = r.nextInt(256);
        expect(gmul(a, b), gmul(b, a));
        expect(gmul(gmul(a, b), c), gmul(a, gmul(b, c)));
        expect(gmul(a, b ^ c), gmul(a, b) ^ gmul(a, c));
      }
    });
  });

  group('Shamir 2-of-3', () {
    test('every pair, both orders, reconstructs; wire round trip too', () async {
      for (final len in [16, 32, 33, 64, 1000]) {
        for (var it = 0; it < 8; it++) {
          final secret = rnd(r, len);
          final sh = await Shamir.split(secret);
          expect(sh.map((s) => s.x), [1, 2, 3]);
          for (final (i, j) in [(0, 1), (1, 0), (0, 2), (2, 0), (1, 2), (2, 1)]) {
            expect(await Shamir.combine([sh[i], sh[j]]), secret, reason: 'len=$len pair $i,$j');
            final w = [
              Share.fromBytes(sh[i].toBytes()),
              Share.fromBytes(sh[j].toBytes())
            ];
            expect(await Shamir.combine(w), secret);
          }
        }
      }
    });

    test('library field arithmetic agrees with the independent reference', () async {
      for (final len in [16, 33, 100]) {
        final secret = rnd(r, len);
        final sh = await Shamir.split(secret);
        for (var i = 0; i < len; i++) {
          final c = sh[0].y[i] ^ secret[i];
          expect(sh[1].y[i], secret[i] ^ gmul(c, 2));
          expect(sh[2].y[i], secret[i] ^ gmul(c, 3));
        }
      }
    });

    test('3-of-5 and 4-of-9: every k-subset reconstructs, via lib and reference', () async {
      Iterable<List<int>> subsets(int n, int k, [int start = 0, List<int> cur = const []]) sync* {
        if (cur.length == k) {
          yield cur;
          return;
        }
        for (var i = start; i < n; i++) {
          yield* subsets(n, k, i + 1, [...cur, i]);
        }
      }

      for (final (n, k) in [(5, 3), (9, 4)]) {
        final secret = rnd(r, 20);
        final sh = await Shamir.split(secret, shares: n, threshold: k);
        for (final sub in subsets(n, k)) {
          expect(await Shamir.combine([for (final i in sub) sh[i]]), secret, reason: '$n/$k $sub');
          for (var b = 0; b < secret.length; b++) {
            expect(refInterp([for (final i in sub) sh[i].x], [for (final i in sub) sh[i].y[b]]), secret[b]);
          }
        }
        // k-1 shares never suffice.
        for (final sub in subsets(n, k - 1)) {
          await expectLater(Shamir.combine([for (final i in sub) sh[i]]),
              throwsA(isA<SsbCryptoException>()));
        }
      }
    });

    test('255 shares: all x unique and in 1..255, random pairs reconstruct', () async {
      final secret = rnd(r, 16);
      final sh = await Shamir.split(secret, shares: 255, threshold: 2);
      expect(sh.map((s) => s.x).toSet().length, 255);
      expect(sh.last.x, 255);
      for (var i = 0; i < 30; i++) {
        final a = r.nextInt(255);
        var b = r.nextInt(255);
        if (b == a) b = (b + 1) % 255;
        expect(await Shamir.combine([sh[a], sh[b]]), secret);
      }
    });

    test('a single share never equals the secret and cannot be combined', () async {
      for (final len in [16, 32, 33, 64, 1000]) {
        final secret = rnd(r, len);
        final sh = await Shamir.split(secret);
        for (final s in sh) {
          expect(s.y, isNot(secret));
          await expectLater(Shamir.combine([s]), throwsA(isA<SsbCryptoException>()));
        }
      }
      await expectLater(Shamir.combine([]), throwsA(isA<SsbCryptoException>()));
    });

    test('share y-values are uniform whatever the secret (16-byte secrets all-0x00 / all-0xFF)', () async {
      for (final secretByte in [0x00, 0xFF]) {
        final counts = List<int>.filled(256, 0);
        const n = 6000;
        for (var i = 0; i < n; i++) {
          final sh = await Shamir.split(Uint8List(16)..fillRange(0, 16, secretByte));
          counts[sh[0].y[0]]++;
        }
        final exp = n / 256;
        var chi = 0.0;
        for (final c in counts) {
          chi += (c - exp) * (c - exp) / exp;
        }
        expect(counts.where((c) => c == 0).length, lessThan(5), reason: 'secret=$secretByte');
        expect(chi, lessThan(400), reason: 'chi2=$chi (df 255) secret=$secretByte');
      }
    });

    test('FINDING-CANDIDATE: documented contract: secrets must be >= 16 bytes (keyCheck pins low-entropy secrets)', () async {
      // Every share carries keyCheck = HKDF(secret)[0..8], so a single share
      // pins a LOW-ENTROPY secret exactly. The fix is the documented contract:
      // split() refuses secrets shorter than Shamir.minSecretLength, so only
      // (uniformly random) high-entropy secrets are ever shared.
      expect(Shamir.minSecretLength, greaterThanOrEqualTo(16));
      for (final len in [0, 1, 2, 8, 15]) {
        await expectLater(Shamir.split(rnd(r, len)), throwsA(isA<SsbCryptoException>()), reason: 'len=$len');
      }
      for (final len in [16, 32]) {
        final sh = await Shamir.split(rnd(r, len));
        expect(sh.length, 3);
        expect(sh[0].keyCheck.length, 8); // the tag leaks at most 64 bits of a hash of a >=128-bit secret
      }
    });
  });

  group('Shamir input validation and misuse', () {
    test('bad split parameters rejected', () async {
      final s = rnd(r, 16);
      for (final (n, k) in [(3, 1), (3, 0), (3, 4), (1, 2), (256, 2), (0, 0), (3, -1)]) {
        await expectLater(Shamir.split(s, shares: n, threshold: k),
            throwsA(isA<SsbCryptoException>()), reason: '$n/$k');
      }
      await expectLater(Shamir.split(Uint8List(0)), throwsA(isA<SsbCryptoException>()));
    });

    test('Share.fromBytes structural rejection', () {
      for (var len = 0; len < 12; len++) {
        expect(() => Share.fromBytes(Uint8List(len)..fillRange(0, len, 1)),
            throwsA(isA<SsbCryptoException>()), reason: 'len=$len');
      }
      Uint8List mk(int v, int t, int x) => Uint8List.fromList([v, t, x, ...List.filled(8, 7), 9]);
      expect(Share.fromBytes(mk(1, 2, 1)).x, 1);
      expect(() => Share.fromBytes(mk(0, 2, 1)), throwsA(isA<SsbCryptoException>()));
      expect(() => Share.fromBytes(mk(2, 2, 1)), throwsA(isA<SsbCryptoException>()));
      expect(() => Share.fromBytes(mk(1, 1, 1)), throwsA(isA<SsbCryptoException>()));
      expect(() => Share.fromBytes(mk(1, 0, 1)), throwsA(isA<SsbCryptoException>()));
      expect(() => Share.fromBytes(mk(1, 2, 0)), throwsA(isA<SsbCryptoException>()));
    });

    test('duplicate / zero / out-of-range indexes never yield a wrong or silent result', () async {
      final secret = rnd(r, 32);
      final sh = await Shamir.split(secret);
      final f = Fails();
      // same share twice
      await f.mustFail('dup share', () => Shamir.combine([sh[0], sh[0]]));
      // distinct objects, same x
      await f.mustFail('dup x', () => Shamir.combine([sh[1], Share(2, 2, sh[1].keyCheck, Uint8List.fromList(sh[1].y))]));
      // zero index (f(0) is the secret slot) with attacker-chosen y
      for (final y0 in [Uint8List(32), rnd(r, 32), rnd(r, 32)]) {
        await f.mustFail('x=0', () => Shamir.combine([Share(2, 0, sh[0].keyCheck, y0), sh[1]]));
        await f.mustFail('x=0 first', () => Shamir.combine([sh[0], Share(2, 0, sh[0].keyCheck, y0)]));
      }
      // out of range (256+): not reachable from the 1-byte wire format. Must
      // never produce a WRONG secret: either a typed error or the correct one.
      for (final x in [256, 257, 258, 511, 512, 1 << 20, -1, -255]) {
        for (final pair in [
          [Share(2, x, sh[0].keyCheck, sh[0].y), sh[1]],
          [sh[0], Share(2, x, sh[1].keyCheck, sh[1].y)],
        ]) {
          try {
            final out = await Shamir.combine(pair);
            f.check(constantTimeEquals(out, secret), 'x=$x WRONG SECRET returned');
          } on SsbCryptoException {
            f.check(true, '');
          } catch (e) {
            f.add('x=$x WRONG-ERROR ${e.runtimeType}');
          }
        }
      }
      f.done();
    });

    test('shares of different secrets / different splits never combine', () async {
      final f = Fails();
      for (var i = 0; i < 20; i++) {
        final a = await Shamir.split(rnd(r, 32));
        final b = await Shamir.split(rnd(r, 32));
        for (final (p, q) in [(0, 1), (1, 2), (0, 2)]) {
          await f.mustFail('A$p+B$q', () => Shamir.combine([a[p], b[q]]));
        }
        // same secret, two independent splits (different polynomials)
        final sec = rnd(r, 32);
        final c = await Shamir.split(sec), d = await Shamir.split(sec);
        await f.mustFail('same secret, two splits', () => Shamir.combine([c[0], d[1]]));
        // different lengths and different thresholds
        final e = await Shamir.split(rnd(r, 33));
        await f.mustFail('len mismatch', () => Shamir.combine([a[0], e[1]]));
        final g = await Shamir.split(sec, shares: 5, threshold: 3);
        await f.mustFail('threshold mismatch', () => Shamir.combine([c[0], g[1]]));
      }
      f.done();
    });

    test('flipping any bit of a serialized share makes the pair fail to combine', () async {
      final secret = rnd(r, 32);
      final sh = await Shamir.split(secret);
      final f = Fails();
      for (final idx in [0, 1]) {
        final other = sh[1 - idx];
        final wire = sh[idx].toBytes();
        for (var i = 0; i < wire.length; i++) {
          for (var bit = 0; bit < 8; bit++) {
            final t = flip(wire, i, 1 << bit);
            await f.mustFail('share$idx byte$i bit$bit', () async {
              final s = Share.fromBytes(t);
              return Shamir.combine(idx == 0 ? [s, other] : [other, s]);
            });
          }
        }
      }
      f.done();
    });

    test('corrupted y or keyCheck on one of three shares is detected when it is used', () async {
      final secret = rnd(r, 32);
      final sh = await Shamir.split(secret);
      final bad = Share(2, 1, sh[0].keyCheck, flip(sh[0].y, 5));
      await expectLater(Shamir.combine([bad, sh[1]]), throwsA(isA<SsbCryptoException>()));
      await expectLater(Shamir.combine([bad, sh[2]]), throwsA(isA<SsbCryptoException>()));
    });

    test('FINDING-CANDIDATE: duplicate share listed first must not mask enough distinct shares', () async {
      // combine() counts DISTINCT x (>= k) but then interpolates over the first
      // k list entries, so [s1, s1, s2] has 2 distinct shares yet fails.
      final secret = rnd(r, 32);
      final sh = await Shamir.split(secret);
      expect(await Shamir.combine([sh[0], sh[0], sh[1]]), secret);
    });

    test('extra shares beyond k are accepted without validation (documented behaviour probe)', () async {
      final secret = rnd(r, 32);
      final sh = await Shamir.split(secret);
      final junk = Share(2, 3, sh[2].keyCheck, rnd(r, 32));
      // Either the correct secret or a clean error: never a wrong secret.
      try {
        final out = await Shamir.combine([sh[0], sh[1], junk]);
        expect(out, secret);
      } on SsbCryptoException {
        // acceptable
      }
    });
  });
}
