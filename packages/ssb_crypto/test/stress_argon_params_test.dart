@Timeout(Duration(minutes: 3))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

/// Argon2 parameters travel with the vault (server-stored => attacker-influenced).
void main() {
  final sk = Uint8List(16)..fillRange(0, 16, 7), salt = Uint8List(16)..fillRange(0, 16, 9);

  test('Argon2Params.fromJson: junk JSON is a clean typed error (not TypeError/CastError)', () async {
    final f = Fails();
    for (final j in <Map<String, dynamic>>[
      {}, {'m': 1}, {'m': 'x', 't': 1, 'p': 1}, {'m': 1.5, 't': 1, 'p': 1}, {'m': null, 't': null, 'p': null},
    ]) {
      await f.mustFail('fromJson $j', () => Argon2Params.fromJson(j));
    }
    f.done();
  });

  test('FINDING-CANDIDATE: parameters below Argon2Params.minimum are refused (downgrade protection)', () async {
    // Doc comment: "calibrated per device at setup, never below [minimum]".
    final f = Fails();
    for (final j in <Map<String, int>>[
      {'m': 8, 't': 1, 'p': 1}, {'m': 1024, 't': 1, 'p': 1}, {'m': 65535, 't': 3, 'p': 1}, {'m': 65536, 't': 1, 'p': 1},
    ]) {
      await f.mustFail('below-min $j', () async {
        final p = Argon2Params.fromJson(j);
        return Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: sk, accountSalt: salt, params: p);
      });
    }
    f.done();
  });

  test('zero / negative parameters are a clean typed error (and do not hang)', () async {
    final f = Fails();
    for (final j in <Map<String, int>>[
      {'m': 0, 't': 1, 'p': 1}, {'m': 1024, 't': 0, 'p': 1}, {'m': 1024, 't': 1, 'p': 0},
      {'m': -1, 't': 1, 'p': 1}, {'m': 1024, 't': -1, 'p': 1}, {'m': 1024, 't': 1, 'p': -1},
      {'m': 4, 't': 1, 'p': 1},
    ]) {
      await f.mustFail('params $j', () => Unlock.deriveUnlockKey(
          passphrase: 'pw', secretKey: sk, accountSalt: salt, params: Argon2Params.fromJson(j)));
    }
    f.done();
  });

  test('derivation is deterministic and every input matters (testOnly params)', () async {
    final base = await Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: sk, accountSalt: salt, params: Argon2Params.testOnly);
    expect(await Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: sk, accountSalt: salt, params: Argon2Params.testOnly), base);
    expect(await Unlock.deriveUnlockKey(passphrase: 'pw2', secretKey: sk, accountSalt: salt, params: Argon2Params.testOnly), isNot(base));
    expect(await Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: flip(sk, 0), accountSalt: salt, params: Argon2Params.testOnly), isNot(base));
    expect(await Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: sk, accountSalt: flip(salt, 15), params: Argon2Params.testOnly), isNot(base));
    expect(await Unlock.deriveUnlockKey(passphrase: 'pw', secretKey: sk, accountSalt: salt,
        params: const Argon2Params.testing(memoryKiB: 1024, iterations: 2, parallelism: 1)), isNot(base));
  });
}
