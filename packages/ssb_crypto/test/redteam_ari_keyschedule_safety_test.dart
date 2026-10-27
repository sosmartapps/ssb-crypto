// Regression tests for two follow-up reports (external, 2026-10-27):
// Hpke.keySchedule and SafetyNumber.fingerprint read caller-owned buffers
// AFTER an await. Same root cause as SSB-2026-001: Dart runs an async body
// synchronously up to its first await, so a caller that wipes or overwrites
// a buffer right after the call returns its Future changed what the function
// went on to read, with no error.
//
//  * keySchedule built its suite id synchronously, then read `info` after the
//    first await (info_hash) and `sharedSecret` after the second (secret): a
//    mid-derivation overwrite gave a different key schedule, silently.
//  * fingerprint read `publicKey` inside all 5200 loop iterations: an
//    overwrite after the first hash gave a different safety number, silently.
//
// Each test starts the call, mutates the buffers synchronously, awaits, and
// compares with the result computed from pristine copies.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Uint8List _copy(Uint8List b) => Uint8List.fromList(b);

Uint8List _det(int n, int seed) =>
    Uint8List.fromList([for (var i = 0; i < n; i++) ((i * 31 + seed * 17 + 5) & 0xff) | 1]);

String _ks(HpkeKeySchedule k) => [
      hexEncode(k.key),
      hexEncode(k.baseNonce),
      hexEncode(k.exporterSecret),
      hexEncode(k.context),
    ].join('|');

void main() {
  const kem = Hpke.kemXWing, kdf = Hpke.kdfHkdfSha256, aead = Hpke.aeadAes256Gcm;

  group('Hpke.keySchedule snapshots sharedSecret and info before its first await', () {
    final ss0 = _det(32, 1), info0 = _det(40, 2);

    test('wiping sharedSecret right after the call does not change the schedule', () async {
      final want = _ks(await Hpke.keySchedule(_copy(ss0), _copy(info0), kemId: kem, kdfId: kdf, aeadId: aead));
      final ss = _copy(ss0), info = _copy(info0);
      final pending = Hpke.keySchedule(ss, info, kemId: kem, kdfId: kdf, aeadId: aead);
      wipe(ss);
      expect(_ks(await pending), want);
    });

    test('overwriting info right after the call does not change the schedule', () async {
      final want = _ks(await Hpke.keySchedule(_copy(ss0), _copy(info0), kemId: kem, kdfId: kdf, aeadId: aead));
      final ss = _copy(ss0), info = _copy(info0);
      final pending = Hpke.keySchedule(ss, info, kemId: kem, kdfId: kdf, aeadId: aead);
      info.fillRange(0, info.length, 0x41);
      expect(_ks(await pending), want);
    });

    test('mutating growable List<int> arguments is equally harmless', () async {
      final want = _ks(await Hpke.keySchedule(_copy(ss0), _copy(info0), kemId: kem, kdfId: kdf, aeadId: aead));
      final ss = _copy(ss0).toList();
      final info = _copy(info0).toList();
      final pending = Hpke.keySchedule(ss, info, kemId: kem, kdfId: kdf, aeadId: aead);
      ss.fillRange(0, ss.length, 0);
      info
        ..clear()
        ..add(7);
      expect(_ks(await pending), want);
    });

    test('the derived schedule is not a function of the mutated bytes', () async {
      final ss = _copy(ss0), info = _copy(info0);
      final pending = Hpke.keySchedule(ss, info, kemId: kem, kdfId: kdf, aeadId: aead);
      wipe(ss);
      info.fillRange(0, info.length, 0);
      final got = await pending;
      final zeroed = await Hpke.keySchedule(Uint8List(32), Uint8List(40), kemId: kem, kdfId: kdf, aeadId: aead);
      expect(_ks(got), isNot(_ks(zeroed)), reason: 'schedule was derived from the wiped buffers');
    });
  });

  group('SafetyNumber.fingerprint snapshots publicKey before its first await', () {
    final pk0 = _det(1216, 3);

    test('wiping publicKey right after the call does not change the fingerprint', () async {
      final want = await SafetyNumber.fingerprint(beneficiaryId: 'ben-1', publicKey: _copy(pk0));
      final pk = _copy(pk0);
      final pending = SafetyNumber.fingerprint(beneficiaryId: 'ben-1', publicKey: pk);
      wipe(pk);
      expect(await pending, want);
    });

    test('overwriting publicKey right after the call does not change the fingerprint', () async {
      final want = await SafetyNumber.fingerprint(beneficiaryId: 'ben-2', publicKey: _copy(pk0));
      final pk = _copy(pk0);
      final pending = SafetyNumber.fingerprint(beneficiaryId: 'ben-2', publicKey: pk);
      pk.fillRange(0, pk.length, 0xEE);
      expect(await pending, want);
    });

    test('a substituted key still gives a different number (the defence itself is intact)', () async {
      final a = await SafetyNumber.fingerprint(beneficiaryId: 'ben-3', publicKey: _copy(pk0));
      final other = _copy(pk0)..[600] ^= 1;
      final b = await SafetyNumber.fingerprint(beneficiaryId: 'ben-3', publicKey: other);
      expect(a, isNot(b));
    });
  });
}
