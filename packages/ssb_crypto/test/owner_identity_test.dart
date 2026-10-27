// Owner identity: the self-certifying vault id (SSB-2026-003).
// The known-answer vector is pinned in vectors/owner_identity_kat.json and
// also checked by an independent server-side implementation, so the app and the
// server agree on the derivation and the signed bytes.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Uint8List _flip(Uint8List b, int i) => Uint8List.fromList(b)..[i] ^= 1;

void main() {
  final kat = jsonDecode(File('test/vectors/owner_identity_kat.json').readAsStringSync())
      as Map<String, dynamic>;
  final katKey = Uint8List.fromList(List.filled(32, 1));
  final katNonce = hexDecode(kat['nonce'] as String);

  group('derivation', () {
    test('known-answer vector (Vault Key = 32 x 0x01)', () async {
      final id = await OwnerIdentity.derive(katKey);
      expect(hexEncode(id.publicKey), kat['pk']);
      expect(id.vaultId, kat['id']);
      expect(OwnerIdentity.vaultIdFor(hexDecode(kat['pk'] as String)), kat['id']);
      final sig = await OwnerIdentity.signChallenge(
          vaultKey: katKey, vaultId: id.vaultId, nonce: katNonce);
      expect(hexEncode(sig), kat['sig']); // Ed25519 is deterministic
      final del = await OwnerIdentity.signChallenge(
          vaultKey: katKey, vaultId: id.vaultId, nonce: katNonce,
          purpose: OwnerIdentity.deletePurpose);
      expect(hexEncode(del), kat['sigDelete']);
    });

    test('same Vault Key -> same identity; different key -> different identity', () async {
      final k1 = randomBytes(32), k2 = randomBytes(32);
      final a = await OwnerIdentity.derive(k1), b = await OwnerIdentity.derive(k1);
      final c = await OwnerIdentity.derive(k2);
      expect(hexEncode(a.publicKey), hexEncode(b.publicKey));
      expect(a.vaultId, b.vaultId);
      expect(c.vaultId, isNot(a.vaultId));
      expect(hexEncode(c.publicKey), isNot(hexEncode(a.publicKey)));
    });

    test('id shape: v2_ + 40 hex, stable, and a hash of the key', () async {
      final id = await OwnerIdentity.derive(randomBytes(32));
      expect(RegExp(r'^v2_[0-9a-f]{40}$').hasMatch(id.vaultId), isTrue);
      expect(OwnerIdentity.vaultIdFor(id.publicKey), id.vaultId);
      expect(OwnerIdentity.isSelfCertifyingId(id.vaultId), isTrue);
      expect(OwnerIdentity.isSelfCertifyingId('v_0123456789abcdef'), isFalse);
    });

    test('derive() does not read the Vault Key after it was wiped (snapshot)', () async {
      final k = randomBytes(32);
      final expected = (await OwnerIdentity.derive(k)).vaultId;
      final f = OwnerIdentity.derive(k);
      wipe(k); // wiped while the future is pending
      expect((await f).vaultId, expected);
    });

    test('an empty, short or all-zero key is refused', () async {
      for (final bad in [Uint8List(0), Uint8List(32), Uint8List(31)..fillRange(0, 31, 7)]) {
        await expectLater(OwnerIdentity.derive(bad), throwsA(isA<SsbCryptoException>()));
      }
    });

    test('createSelfCertifying: the id IS the derivation of the keyring\'s Vault Key', () async {
      final ring = await VaultKeyring.createSelfCertifying();
      expect(ring.vaultId, (await OwnerIdentity.derive(ring.vaultKey)).vaultId);
      expect(OwnerIdentity.isSelfCertifyingId(ring.vaultId), isTrue);
      final other = await VaultKeyring.createSelfCertifying();
      expect(other.vaultId, isNot(ring.vaultId));
      ring.dispose();
      other.dispose();
    });
  });

  group('challenge signatures', () {
    late Uint8List vk, nonce;
    late OwnerIdentity id;
    late Uint8List sig;
    setUp(() async {
      vk = randomBytes(32);
      nonce = randomBytes(32);
      id = await OwnerIdentity.derive(vk);
      sig = await OwnerIdentity.signChallenge(vaultKey: vk, vaultId: id.vaultId, nonce: nonce);
    });

    Future<bool> verify({Uint8List? pk, String? vaultId, Uint8List? n, Uint8List? s, String? purpose}) =>
        OwnerIdentity.verifyChallenge(
            publicKey: pk ?? id.publicKey, vaultId: vaultId ?? id.vaultId,
            nonce: n ?? nonce, signature: s ?? sig,
            purpose: purpose ?? OwnerIdentity.authPurpose);

    test('round trip', () async => expect(await verify(), isTrue));

    test('tamper on the vault id, the nonce or the signature fails', () async {
      expect(await verify(vaultId: '${id.vaultId.substring(0, 42)}0'), isFalse);
      expect(await verify(n: _flip(nonce, 0)), isFalse);
      expect(await verify(n: _flip(nonce, 31)), isFalse);
      for (final i in [0, 31, 32, 63]) {
        expect(await verify(s: _flip(sig, i)), isFalse, reason: 'sig byte $i');
      }
      expect(await verify(s: Uint8List(63)), isFalse);
    });

    test('a signature does not verify under another key, and the id must match the key', () async {
      final other = await OwnerIdentity.derive(randomBytes(32));
      expect(await verify(pk: other.publicKey), isFalse);
      // A squatter signs with their OWN key but claims the victim's id.
      final squatterVk = randomBytes(32);
      final squatter = await OwnerIdentity.derive(squatterVk);
      final forged = await OwnerIdentity.signChallenge(
          vaultKey: squatterVk, vaultId: squatter.vaultId, nonce: nonce);
      expect(
          await OwnerIdentity.verifyChallenge(
              publicKey: squatter.publicKey, vaultId: id.vaultId, nonce: nonce, signature: forged),
          isFalse,
          reason: 'the id is not the hash of the presented key');
    });

    test('signing for an id the key does not derive to is refused', () async {
      await expectLater(
          OwnerIdentity.signChallenge(vaultKey: vk, vaultId: 'v_legacy_0123456789', nonce: nonce),
          throwsA(isA<SsbCryptoException>()));
      await expectLater(
          OwnerIdentity.signChallenge(
              vaultKey: randomBytes(32), vaultId: id.vaultId, nonce: nonce),
          throwsA(isA<SsbCryptoException>()));
    });

    test('purposes are separate domains (sign-in cannot be replayed as delete)', () async {
      expect(await verify(purpose: OwnerIdentity.deletePurpose), isFalse);
      final del = await OwnerIdentity.signChallenge(
          vaultKey: vk, vaultId: id.vaultId, nonce: nonce, purpose: OwnerIdentity.deletePurpose);
      expect(await verify(s: del, purpose: OwnerIdentity.deletePurpose), isTrue);
      expect(await verify(s: del), isFalse);
    });

    test('nonce length is bounded on both sides', () async {
      await expectLater(
          OwnerIdentity.signChallenge(vaultKey: vk, vaultId: id.vaultId, nonce: Uint8List(8)),
          throwsA(isA<SsbCryptoException>()));
      expect(await verify(n: Uint8List(8)), isFalse);
      expect(await verify(n: Uint8List(65)), isFalse);
    });

    test('the signed message layout is purpose || lp(vaultId) || u16(len) || nonce', () {
      final m = OwnerIdentity.challengeMessage(id.vaultId, nonce);
      final expected = BytesBuilder()
        ..add(utf8.encode('ssb/v2/owner-auth'))
        ..add([0, 0, 0, id.vaultId.length])
        ..add(utf8.encode(id.vaultId))
        ..add([0, 32])
        ..add(nonce);
      expect(hexEncode(m), hexEncode(expected.toBytes()));
    });
  });
}
