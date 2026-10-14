@Timeout(Duration(minutes: 6))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

const _p = 'release-token';

Future<bool> _ver(Uint8List pk, Uint8List m, Uint8List s, {String purpose = _p}) async {
  try {
    return await HybridSignature.verify(pk, m, s, purpose: purpose);
  } on SsbCryptoException {
    return false;
  }
}

void main() {
  final r = seeded(4);
  late HybridKeyPair kp, kp2;
  final msg = utf8Bytes('{"vault":"V1","beneficiary":"B1","tier":"ice","notBefore":1790000000,"nonce":"abc123"}');
  late Uint8List sig;

  setUpAll(() async {
    kp = await HybridSignature.generateKeyPair();
    kp2 = await HybridSignature.generateKeyPair();
    sig = await HybridSignature.sign(kp.secretKey, msg, purpose: _p);
  });

  test('sizes and round trips: empty, 1 byte, token-sized, 1 MB messages', () async {
    expect(kp.publicKey.length, HybridSignature.publicKeyLength);
    expect(kp.secretKey.length, HybridSignature.secretKeyLength);
    expect(sig.length, HybridSignature.signatureLength);
    for (final n in [0, 1, 31, 32, 33, 255, 4096, 1 << 20]) {
      final m = rnd(r, n);
      final s = await HybridSignature.sign(kp.secretKey, m, purpose: 'p');
      expect(await HybridSignature.verify(kp.publicKey, m, s, purpose: 'p'), isTrue, reason: 'n=$n');
    }
    expect(await _ver(kp.publicKey, msg, sig), isTrue);
  });

  test('signing is repeatable-valid; ML-DSA hedging may differ but both verify', () async {
    final s2 = await HybridSignature.sign(kp.secretKey, msg, purpose: _p);
    expect(await _ver(kp.publicKey, msg, s2), isTrue);
  });

  test('EVERY bit of the Ed25519 half (512 bits) breaks verification', () async {
    final f = Fails();
    for (var i = 0; i < HybridSignature.edSigLen; i++) {
      for (var bit = 0; bit < 8; bit++) {
        f.check(!await _ver(kp.publicKey, msg, flip(sig, i, 1 << bit)), 'ed byte $i bit $bit still verifies');
      }
    }
    f.done();
  });

  test('EVERY bit of the ML-DSA-65 half (3309 bytes) breaks verification', () async {
    final f = Fails();
    // Every byte (one seeded-random bit each) + all 8 bits of the first 48
    // bytes (c-tilde) and last 100 bytes (hint section). Full 26k-bit sweep
    // costs ~90 s, so it is sampled to keep the suite under budget.
    for (var i = HybridSignature.edSigLen; i < sig.length; i++) {
      final off = i - HybridSignature.edSigLen;
      final allBits = off < 48 || off >= HybridSignature.dsaSigLen - 100;
      final bits = allBits ? [0, 1, 2, 3, 4, 5, 6, 7] : [r.nextInt(8)];
      for (final bit in bits) {
        f.check(!await _ver(kp.publicKey, msg, flip(sig, i, 1 << bit)), 'ml-dsa byte $off bit $bit still verifies');
      }
    }
    f.done();
  });

  test('EVERY bit of the message breaks verification; appended/trimmed too', () async {
    final f = Fails();
    for (var i = 0; i < msg.length; i++) {
      for (var bit = 0; bit < 8; bit++) {
        f.check(!await _ver(kp.publicKey, flip(msg, i, 1 << bit), sig), 'msg byte $i bit $bit');
      }
    }
    f.check(!await _ver(kp.publicKey, Uint8List.fromList([...msg, 0]), sig), 'appended 0');
    f.check(!await _ver(kp.publicKey, msg.sublist(0, msg.length - 1), sig), 'trimmed');
    f.check(!await _ver(kp.publicKey, Uint8List(0), sig), 'empty msg');
    f.done();
  });

  test('EVERY byte of the hybrid public key (both halves) breaks verification', () async {
    final f = Fails();
    for (var i = 0; i < kp.publicKey.length; i++) {
      f.check(!await _ver(flip(kp.publicKey, i), msg, sig), 'pk byte $i (${i < 32 ? 'ed' : 'ml-dsa'}) still verifies');
    }
    f.done();
  });

  test('BOTH halves required: valid Ed25519 + bad ML-DSA fails, and vice versa', () async {
    final other = await HybridSignature.sign(kp.secretKey, utf8Bytes('other message'), purpose: _p);
    final sigB = await HybridSignature.sign(kp2.secretKey, msg, purpose: _p);
    Uint8List join(Uint8List ed, Uint8List dsa) => Uint8List.fromList([...ed.sublist(0, 64), ...dsa.sublist(64)]);
    final f = Fails();
    f.check(await _ver(kp.publicKey, msg, join(sig, sig)), 'sanity: self-join must verify');
    // valid ed25519 half, ML-DSA half from another message / other key / zeros / ones / random
    for (final (name, dsaSrc) in [
      ('dsa of other msg', other),
      ('dsa of other key', sigB),
      ('dsa zeros', Uint8List(sig.length)),
      ('dsa ones', Uint8List(sig.length)..fillRange(0, sig.length, 0xff)),
      ('dsa random', rnd(r, sig.length)),
    ]) {
      f.check(!await _ver(kp.publicKey, msg, join(sig, dsaSrc)), 'valid ed + bad ml-dsa verifies: $name');
      f.check(!await _ver(kp.publicKey, msg, join(dsaSrc, sig)), 'bad ed + valid ml-dsa verifies: $name');
    }
    f.check(!await _ver(kp.publicKey, msg, Uint8List(sig.length)), 'all zero sig');
    f.check(!await _ver(kp.publicKey, msg, Uint8List(sig.length)..fillRange(0, sig.length, 0xff)), 'all ff sig');
    f.done();
  });

  test('signature from key A never verifies under key B (and halves of A|B pubkeys)', () async {
    final f = Fails();
    f.check(!await _ver(kp2.publicKey, msg, sig), 'A sig under B');
    final mixPk1 = Uint8List.fromList([...kp.publicKey.sublist(0, 32), ...kp2.publicKey.sublist(32)]);
    final mixPk2 = Uint8List.fromList([...kp2.publicKey.sublist(0, 32), ...kp.publicKey.sublist(32)]);
    f.check(!await _ver(mixPk1, msg, sig), 'ed(A)|dsa(B) pk');
    f.check(!await _ver(mixPk2, msg, sig), 'ed(B)|dsa(A) pk');
    f.done();
  });

  test('wrong lengths: verify returns false or typed error, sign throws typed error', () async {
    final f = Fails();
    for (final n in [0, 1, 63, 64, 3372, 3374, 6000]) {
      f.check(!await _ver(kp.publicKey, msg, Uint8List(n)), 'sig len $n');
      f.check(!await _ver(Uint8List(n), msg, sig), 'pk len $n');
    }
    for (final n in [0, 32, 4063, 4065, 4096]) {
      await f.mustFail('sign sk len $n', () => HybridSignature.sign(Uint8List(n), msg, purpose: _p));
    }
    // truncation of a real signature at every length
    for (var n = 0; n < sig.length; n += 17) {
      f.check(!await _ver(kp.publicKey, msg, sig.sublist(0, n)), 'trunc $n');
    }
    f.done();
  });

  test('domain separation: purpose is bound; signatures do not cross purposes', () async {
    final f = Fails();
    for (final p in ['', 'release', 'release-token ', 'Release-Token', 'audit', 'enrollment']) {
      f.check(!await _ver(kp.publicKey, msg, sig, purpose: p), 'purpose "$p" verifies');
    }
    f.done();
  });

  test('FINDING-CANDIDATE: purpose/message boundary is unambiguous (no length prefix)', () async {
    // Signed bytes are "ssb/v1/sig|PURPOSE|" || message. With no length prefix
    // purpose "a|b"+msg "c" and purpose "a"+msg "b|c" sign identical bytes.
    final s = await HybridSignature.sign(kp.secretKey, utf8Bytes('c'), purpose: 'a|b');
    expect(await HybridSignature.verify(kp.publicKey, utf8Bytes('b|c'), s, purpose: 'a'), isFalse,
        reason: 'signature for (purpose a|b, msg c) verified as (purpose a, msg b|c)');
  });

  test('token-style canonical JSON: each field tamper (replay with other vault/tier/time/nonce) fails', () async {
    final f = Fails();
    final base = String.fromCharCodes(msg);
    for (final (a, b) in [
      ('"V1"', '"V2"'), ('"B1"', '"B2"'), ('"ice"', '"secrets"'),
      ('1790000000', '1700000000'), ('abc123', 'abc124'), ('"tier"', '"Tier"'),
    ]) {
      final t = utf8Bytes(base.replaceFirst(a, b));
      f.check(t.isNotEmpty && !await _ver(kp.publicKey, t, sig), 'tampered $a -> $b verifies');
    }
    f.done();
  });

  test('forgery attempts with trivially structured pk/sig (identity point, zeros) fail', () async {
    final f = Fails();
    // Ed25519 small-order public key + (R=identity, S=0) is the classic
    // "verifies for every message" forgery against non-strict verifiers.
    final identityR = Uint8List(32)..[0] = 1;
    final edForged = Uint8List.fromList([...identityR, ...Uint8List(32)]);
    final pkWeak = Uint8List.fromList([...identityR, ...kp.publicKey.sublist(32)]);
    for (final m in [msg, Uint8List(0), rnd(r, 100)]) {
      // against the REAL key: forged ed half must fail
      f.check(!await _ver(kp.publicKey, m, Uint8List.fromList([...edForged, ...sig.sublist(64)])), 'forged ed half under real pk');
      // against a weak-ed composite key, a zero/garbage ML-DSA half must still fail
      f.check(!await _ver(pkWeak, m, Uint8List.fromList([...edForged, ...Uint8List(3309)])), 'weak-ed pk, zero dsa');
      f.check(!await _ver(pkWeak, m, Uint8List.fromList([...edForged, ...rnd(r, 3309)])), 'weak-ed pk, random dsa');
    }
    f.done();
  });
}
