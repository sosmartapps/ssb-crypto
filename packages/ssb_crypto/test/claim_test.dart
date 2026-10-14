import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('the token comes from the printed key alone, and the stored value is not it',
      () async {
    final sk = randomBytes(2400);
    final token = await ClaimToken.compute(beneficiarySecretKey: sk);
    final stored = await ClaimToken.verifier(token);

    expect(token.length, 128);
    expect(stored.length, 128);
    expect(stored, isNot(token), reason: 'the server must not hold a usable token');

    // Same Kit, same token -- they can come back tomorrow.
    expect(await ClaimToken.compute(beneficiarySecretKey: sk), token);
  });

  test('one wrong byte of the secret key changes everything', () async {
    final sk = randomBytes(2400);
    final tweaked = Uint8List.fromList(sk)..[7] ^= 1;
    expect(await ClaimToken.compute(beneficiarySecretKey: sk),
        isNot(await ClaimToken.compute(beneficiarySecretKey: tweaked)));
  });

  test('two beneficiaries never collide', () async {
    final tokens = <String>{};
    for (var i = 0; i < 20; i++) {
      tokens.add(await ClaimToken.compute(beneficiarySecretKey: randomBytes(2400)));
    }
    expect(tokens.length, 20);
  });

  // The Dart client and the Node server both compute this. If either side
  // drifts, a real beneficiary gets "that did not match" while holding a
  // valid Kit -- so both sides pin the same vector.
  test('golden vector (mirrored in backend/functions/src/claim.test.js)', () async {
    final sk = Uint8List.fromList([for (var i = 0; i < 2400; i++) i % 256]);
    final token = await ClaimToken.compute(beneficiarySecretKey: sk);
    expect(
        token,
        '10e5c235e13a19cabb821fa5bcca933c67f4f67fbf33ce39e8f51b16ec610f55'
        'a01aa8edef718d08a122c74ab479a2517424a6066170700163007ca29c19778e');
    expect(
        await ClaimToken.verifier(token),
        'dbe0c93279a9a0fbb19bdefa5e6e7dc6ae294a39213c44564ea77fb76e6d4117'
        'ee250d80f244a7df56290b17bce4e737dceb56f0c02969b5b27221d707f765d6');
  });

  test('the owner token comes back from the Vault Key alone', () async {
    final vaultKey = randomBytes(32);
    final t = await OwnerToken.compute(vaultId: 'v1', vaultKey: vaultKey);
    // Restoring the same vault on a new phone must produce the same identity,
    // or the owner loses the ability to stop a release.
    expect(await OwnerToken.compute(vaultId: 'v1', vaultKey: vaultKey), t);
    expect(await OwnerToken.compute(vaultId: 'v2', vaultKey: vaultKey), isNot(t));
    expect(await OwnerToken.verifier(t), isNot(t));
  });
}
