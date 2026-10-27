// Phase 0 hardening regressions from the 2026-10-20 red team (see the
// redteam_*_test.dart PoCs in the review scratch tree). Every attack those
// PoCs demonstrated as BROKEN must now be REJECTED with SsbCryptoException --
// never accepted, and never a raw TypeError/RangeError. Nothing here changes
// a wire format; these are tripwires and strictness only.
//
// SSB-2026-002 freshness / tier-rollback PoCs are covered by
// freshness_regression_test.dart (Phase 1).
import 'dart:async';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

Uint8List _zeros(int n) => Uint8List(n);
Uint8List _cat(List<List<int>> p) => concatBytes(p);

/// `OK`, `SSB:<msg>` or `OTHER:<type>` -- so a test can insist on the typed
/// error specifically (a null-check TypeError leaking out is itself a bug).
Future<String> _outcome(FutureOr<dynamic> Function() f) async {
  try {
    await f();
    return 'OK';
  } on SsbCryptoException catch (e) {
    return 'SSB:${e.message}';
  } catch (e) {
    return 'OTHER:${e.runtimeType}';
  }
}

void main() {
  late XWingKeyPair ben;
  setUpAll(() async => ben = await XWing.generateKeyPair());

  group('B1 zero / degenerate X-Wing public keys are refused', () {
    test('XWing.validatePublicKey', () {
      expect(() => XWing.validatePublicKey(_zeros(1216)), throwsSsb);
      expect(() => XWing.validatePublicKey(_cat([_zeros(1184), ben.publicKey.sublist(1184)])), throwsSsb);
      expect(() => XWing.validatePublicKey(_cat([ben.publicKey.sublist(0, 1184), _zeros(32)])), throwsSsb);
      expect(() => XWing.validatePublicKey(ben.publicKey.sublist(0, 1215)), throwsSsb);
      expect(() => XWing.validatePublicKey(_cat([ben.publicKey, [0]])), throwsSsb);
      expect(() => XWing.validatePublicKey(_zeros(0)), throwsSsb);
      expect(() => XWing.validatePublicKey(ben.publicKey), returnsNormally);
    });

    test('XWing.encapsulate / encapsulateDerand (PoC 7c)', () async {
      final eseed = randomBytes(64);
      for (final pk in [
        _zeros(1216),
        _cat([_zeros(1184), ben.publicKey.sublist(1184)]),
        _cat([ben.publicKey.sublist(0, 1184), _zeros(32)]),
        ben.publicKey.sublist(0, 1215),
        _zeros(0),
      ]) {
        expect(await _outcome(() => XWing.encapsulate(pk)), 'SSB:bad public key', reason: 'len ${pk.length}');
        expect(await _outcome(() => XWing.encapsulateDerand(pk, eseed)), 'SSB:bad public key');
      }
      // A good key still encapsulates, and a bad eseed is still its own error.
      expect(await _outcome(() => XWing.encapsulateDerand(ben.publicKey, eseed)), 'OK');
      expect(await _outcome(() => XWing.encapsulateDerand(ben.publicKey, randomBytes(63))), 'SSB:bad encapsulation input');
    });

    test('low-order X25519 peer point (all-zero shared secret) is refused', () async {
      // pkX = 1 is a low-order point on Curve25519: X25519(e, 1) = 0 for every e.
      final lowOrder = Uint8List(32)..[0] = 1;
      final pk = _cat([ben.publicKey.sublist(0, 1184), lowOrder]);
      expect(await _outcome(() => XWing.encapsulate(pk)), 'SSB:bad public key');
      expect(await _outcome(() => Hpke.seal(pk, utf8Bytes('x'))), 'SSB:bad public key');
    });

    test('Hpke.seal to a zero / zero-half key is refused before any plaintext is used (PoC 7g)', () async {
      final info = Release.s2Info('v', 'A', Tier.ice, epoch: 1);
      final secret = utf8Bytes('the S2 share bytes');
      expect(await _outcome(() => Hpke.seal(_zeros(1216), secret, info: info)), 'SSB:bad public key');
      expect(await _outcome(() => Hpke.seal(_cat([_zeros(1184), ben.publicKey.sublist(1184)]), secret)), 'SSB:bad public key');
      expect(await _outcome(() => Hpke.seal(_cat([ben.publicKey.sublist(0, 1184), _zeros(32)]), secret)), 'SSB:bad public key');
      expect(await _outcome(() => Hpke.seal(ben.publicKey.sublist(0, 1215), secret)), 'SSB:bad public key');
      expect(await _outcome(() => Hpke.seal(_zeros(0), secret)), 'SSB:bad public key');
      // Round trip for a real key is unchanged.
      final sealed = await Hpke.seal(ben.publicKey, secret, info: info);
      expect(await Hpke.open(ben.secretKey, sealed, info: info), secret);
    });

    test('Release.create to a zeroed beneficiary key is refused (PoC 7h)', () async {
      final tk = randomBytes(32);
      Future<String> create(Uint8List pk) => _outcome(() => Release.create(
          vaultId: 'v', beneficiaryId: 'A', tier: Tier.ice, tierKey: tk, beneficiaryPublicKey: pk, epoch: 1));
      expect(await create(_zeros(1216)), 'SSB:bad public key');
      expect(await create(_cat([_zeros(1184), ben.publicKey.sublist(1184)])), 'SSB:bad public key');
      expect(await create(_cat([ben.publicKey.sublist(0, 1184), _zeros(32)])), 'SSB:bad public key');
      expect(await create(ben.publicKey.sublist(0, 1215)), 'SSB:bad public key');
      expect(await create(ben.publicKey), 'OK');
    });
  });

  group('B2 VaultKeyring fails closed on a partial tier map', () {
    late VaultKeyring kr;
    late Uint8List kek, wvk, manifest;
    late Map<Tier, Uint8List> wtk;
    late InMemoryAnchor anchor;
    setUp(() async {
      anchor = InMemoryAnchor();
      kr = VaultKeyring.create('v', anchor: anchor);
      kek = randomBytes(32);
      wvk = await kr.wrapVaultKey(kek, slot: 'unlock', epoch: 1);
      wtk = {for (final t in Tier.values) t: await kr.wrapTierKey(t)};
      manifest = await kr.sealManifest(items: const []);
      await kr.commitManifest();
    });

    Future<String> open(Map<Tier, Uint8List> m, {Uint8List? k}) => _outcome(() => VaultKeyring.open(
        vaultId: 'v', kek: k ?? kek, slot: 'unlock', wrappedVaultKey: wvk, slotEpochs: kr.slotEpochs,
        manifestBlob: manifest, wrappedTierKeys: m, items: const [], anchor: anchor));
    Future<String> fromVk(Uint8List vk, Map<Tier, Uint8List> m) =>
        _outcome(() => VaultKeyring.fromVaultKey(vaultId: 'v', vaultKey: vk, manifestBlob: manifest,
            wrappedTierKeys: m, items: const [], anchor: anchor));

    test('open(): every tier required (PoC 11a)', () async {
      for (final missing in Tier.values) {
        final partial = Map<Tier, Uint8List>.from(wtk)..remove(missing);
        expect(await open(partial), 'SSB:missing tier key', reason: 'missing ${missing.name}');
      }
      expect(await open(const {}), 'SSB:missing tier key');
      expect(await open(wtk), 'OK');
    });

    test('fromVaultKey(): every tier required, vault key must be 32 non-zero bytes (PoC 11a/11c)', () async {
      final vk = Uint8List.fromList(kr.vaultKey);
      for (final missing in Tier.values) {
        final partial = Map<Tier, Uint8List>.from(wtk)..remove(missing);
        expect(await fromVk(vk, partial), 'SSB:missing tier key', reason: 'missing ${missing.name}');
      }
      expect(await fromVk(vk, const {}), 'SSB:missing tier key');
      expect(await fromVk(vk.sublist(0, 31), wtk), 'SSB:bad vault key');
      expect(await fromVk(_cat([vk, [1]]), wtk), 'SSB:bad vault key');
      expect(await fromVk(_zeros(32), wtk), 'SSB:bad vault key');
      expect(await fromVk(_zeros(0), const {}), 'SSB:bad vault key');
      expect(await fromVk(vk.sublist(0, 31), const {}), 'SSB:bad vault key');
      expect(await fromVk(vk, wtk), 'OK');
    });

    test('a wrong-passphrase open with a FULL map still fails as before (no new oracle)', () async {
      expect(await open(wtk, k: randomBytes(32)), 'SSB:decrypt failed');
    });

    test('missing-tier access on a hand-built keyring is the typed error, and rotate never mints (PoC 11a)', () async {
      // The public tierKeys map is mutable; simulate a tier going missing.
      final ring = await VaultKeyring.open(
          vaultId: 'v', kek: kek, slot: 'unlock', wrappedVaultKey: wvk, slotEpochs: kr.slotEpochs,
          manifestBlob: manifest, wrappedTierKeys: wtk, items: const [], anchor: anchor);
      wipe(ring.tierKeys.remove(Tier.secrets));
      expect(await _outcome(() => ring.tierKey(Tier.secrets)), 'SSB:missing tier key');
      expect(await _outcome(() => ring.wrapTierKey(Tier.secrets)), 'SSB:missing tier key');
      expect(await _outcome(() => ring.rotateTier(Tier.secrets)), 'SSB:missing tier key');
      expect(ring.tierKeys.containsKey(Tier.secrets), isFalse, reason: 'rotateTier must not mint a key');
      expect(ring.tierEpochs[Tier.secrets], 1, reason: 'nor bump the epoch');
      // The tiers that are present still work.
      expect(await _outcome(() => ring.tierKey(Tier.ice)), 'OK');
      expect(await _outcome(() => ring.wrapTierKey(Tier.essentials)), 'OK');
      ring.dispose();
    });
  });

  group('B3 Release.create tier key checks (PoC 6e)', () {
    Future<String> create(Uint8List tk) => _outcome(() => Release.create(
        vaultId: 'v', beneficiaryId: 'A', tier: Tier.ice, tierKey: tk, beneficiaryPublicKey: ben.publicKey, epoch: 1));

    test('all-zero or non-32-byte tier key is refused', () async {
      expect(await create(_zeros(32)), 'SSB:bad tier key');
      for (final n in [0, 15, 16, 31, 33, 64]) {
        expect(await create(randomBytes(n)), 'SSB:bad tier key', reason: 'len $n');
      }
    });

    test('a real tier key still splits and recovers on both paths', () async {
      final tk = randomBytes(32);
      final b = await Release.create(
          vaultId: 'v', beneficiaryId: 'A', tier: Tier.ice, tierKey: tk, beneficiaryPublicKey: ben.publicKey, epoch: 1);
      expect((await Release.recoverOffline(beneficiaryKitCode: b.beneficiaryKitCode, attorneyKitCode: b.attorneyKitCode)).key, tk);
      expect((await Release.recoverWithServerShare(
          vaultId: 'v', beneficiaryId: 'A', tier: Tier.ice,
          beneficiaryKitCode: b.beneficiaryKitCode, sealedServerShare: b.sealedServerShare,
          beneficiarySecretKey: ben.secretKey)).key, tk);
    });
  });

  group('B6 zero / degenerate input tripwires', () {
    test('HybridSignature.sign refuses a wiped (all-zero) key, or a zero half (PoC 8c)', () async {
      final kp = await HybridSignature.generateKeyPair();
      final msg = utf8Bytes('release token');
      expect(await _outcome(() => HybridSignature.sign(_zeros(HybridSignature.secretKeyLength), msg, purpose: 'p')),
          'SSB:bad signing key');
      expect(await _outcome(() => HybridSignature.sign(
          _cat([_zeros(HybridSignature.edSkLen), kp.secretKey.sublist(HybridSignature.edSkLen)]), msg, purpose: 'p')),
          'SSB:bad signing key');
      expect(await _outcome(() => HybridSignature.sign(
          _cat([kp.secretKey.sublist(0, HybridSignature.edSkLen), _zeros(HybridSignature.dsaSkLen)]), msg, purpose: 'p')),
          'SSB:bad signing key');
      // A real key still signs and verifies.
      final sig = await HybridSignature.sign(kp.secretKey, msg, purpose: 'p');
      expect(await HybridSignature.verify(kp.publicKey, msg, sig, purpose: 'p'), isTrue);
    });

    test('Unlock.deriveUnlockKey refuses an all-zero Secret Key, an all-zero salt and an empty passphrase (PoC 9b)', () async {
      final sk = randomBytes(16), salt = randomBytes(16);
      Future<String> derive({String passphrase = 'x', Uint8List? secretKey, Uint8List? accountSalt}) =>
          _outcome(() => Unlock.deriveUnlockKey(
              passphrase: passphrase, secretKey: secretKey ?? sk, accountSalt: accountSalt ?? salt,
              params: Argon2Params.testOnly));
      expect(await derive(secretKey: _zeros(16)), 'SSB:bad unlock input');
      expect(await derive(accountSalt: _zeros(16)), 'SSB:bad unlock input');
      expect(await derive(passphrase: ''), 'SSB:bad unlock input');
      // Length checks are unchanged, and a normal derivation still works.
      expect(await derive(accountSalt: randomBytes(15)), 'SSB:bad unlock input');
      expect(await derive(accountSalt: randomBytes(17)), 'SSB:bad unlock input');
      expect(await derive(), 'OK');
      // openWithPassphrase surfaces the same typed error (what the app catches).
      expect(await _outcome(() => Unlock.openWithPassphrase(
          passphrase: '', secretKey: sk, accountSalt: salt, params: Argon2Params.testOnly,
          open: (k) async => k)), 'SSB:bad unlock input');
    });

    test('ClaimToken.compute refuses an all-zero key; OwnerToken.compute refuses empty / zero vault key (PoC 10a)', () async {
      expect(await _outcome(() => ClaimToken.compute(beneficiarySecretKey: _zeros(32))), 'SSB:bad claim key');
      expect(await _outcome(() => ClaimToken.compute(beneficiarySecretKey: _zeros(64))), 'SSB:bad claim key');
      expect(await _outcome(() => ClaimToken.compute(beneficiarySecretKey: randomBytes(31))), 'SSB:bad claim key');
      expect(await _outcome(() => ClaimToken.compute(beneficiarySecretKey: ben.secretKey)), 'OK');

      expect(await _outcome(() => OwnerToken.compute(vaultId: 'v', vaultKey: _zeros(0))), 'SSB:bad owner key');
      expect(await _outcome(() => OwnerToken.compute(vaultId: 'v', vaultKey: _zeros(32))), 'SSB:bad owner key');
      expect(await _outcome(() => OwnerToken.compute(vaultId: 'v', vaultKey: randomBytes(32))), 'OK');
      // A disposed keyring's (wiped) vault key can no longer mint a token.
      final kr = VaultKeyring.create('v');
      kr.dispose();
      expect(await _outcome(() => OwnerToken.compute(vaultId: 'v', vaultKey: kr.vaultKey)), 'SSB:bad owner key');
    });
  });

  group('ItemCrypto padding is canonical (PoC 3a)', () {
    const v = 'v', id = 'i';
    final tk = randomBytes(32), ik = randomBytes(32);

    /// Builds a SealedItem around a hand-made padded body (what a tampered or
    /// non-conforming encryptor could produce under the owner's own keys).
    Future<SealedItem> mk(Uint8List padded) async => SealedItem(id, Tier.ice,
        await Aead.seal(tk, ik, type: ObjectType.wrappedKey, context: ItemCrypto.keyContext(v, Tier.ice, 1, id)),
        await Aead.seal(ik, padded, type: ObjectType.item, context: ItemCrypto.bodyContext(v, id)));
    Future<String> open(Uint8List padded) async =>
        _outcome(() async => ItemCrypto.open(vaultId: v, tierKey: tk, tierEpoch: 1, item: await mk(padded)));

    test('non-zero bytes in the padding region are rejected', () async {
      expect(await open(_cat([u32be(5), utf8Bytes('hello'), Uint8List(247)..fillRange(0, 247, 0xff)])), 'SSB:decrypt failed');
      expect(await open(_cat([u32be(5), utf8Bytes('hello'), Uint8List(247)..[246] = 1])), 'SSB:decrypt failed');
      expect(await open(_cat([u32be(0), randomBytes(252)])), 'SSB:decrypt failed');
      // The length-prefix checks that already held still hold.
      expect(await open(_cat([u32be(253), randomBytes(252)])), 'SSB:decrypt failed');
      expect(await open(_cat([u32be(0xffffffff), randomBytes(252)])), 'SSB:decrypt failed');
      expect(await open(Uint8List(3)), 'SSB:decrypt failed');
    });

    test('canonical (zero-filled) padding still opens, hand-built and via seal()', () async {
      expect(await open(_cat([u32be(5), utf8Bytes('hello'), Uint8List(247)])), 'OK');
      expect(await open(_cat([u32be(0), Uint8List(252)])), 'OK');
      for (final n in [0, 1, 251, 252, 253, 1000, 70000]) {
        final data = randomBytes(n);
        final item = await ItemCrypto.seal(vaultId: v, tier: Tier.ice, tierKey: tk, tierEpoch: 1, itemId: id, plaintext: data);
        expect(await ItemCrypto.open(vaultId: v, tierKey: tk, tierEpoch: 1, item: item), data, reason: 'len $n');
        final (wk, st) = await ItemCrypto.sealFile(vaultId: v, tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: 'f', data: data);
        expect(await ItemCrypto.openFile(vaultId: v, tier: Tier.ice, tierKey: tk, tierEpoch: 1, fileId: 'f', wrappedKey: wk, stream: st),
            data, reason: 'file len $n');
      }
    });
  });
}
