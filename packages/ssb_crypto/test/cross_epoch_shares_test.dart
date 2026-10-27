// SSB-2026-002 Phase 1 (M2/M4): shares and kits from different key
// generations never combine, and the failure names the cause.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

Future<String> outcome(Future<dynamic> Function() f) async {
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
  group('Shamir across epochs', () {
    test('shares of the same secret at different epochs do not combine', () async {
      final secret = randomBytes(32);
      final e1 = await Shamir.split(secret, epoch: 1);
      final e2 = await Shamir.split(secret, epoch: 2);
      await expectLater(Shamir.combine([e1[0], e2[1]]), throwsSsb);
      await expectLater(Shamir.combine([e2[0], e1[1]]), throwsSsb);
      expect(await Shamir.combine([e1[0], e1[1]]), secret);
      expect(await Shamir.combine([e2[0], e2[2]]), secret);
    });

    test('rewriting the epoch field of a share (salt/check kept) is caught by the keyCheck', () async {
      final secret = randomBytes(32);
      final sh = await Shamir.split(secret, epoch: 7);
      // Forge: same salt, same check, same y, epoch changed on BOTH shares so
      // the equality checks pass; the recomputed check must then fail.
      Share forge(Share s, int epoch) => Share(s.threshold, s.x, epoch, s.salt, s.keyCheck, s.y);
      await expectLater(Shamir.combine([forge(sh[0], 8), forge(sh[1], 8)]), throwsSsb);
      await expectLater(Shamir.combine([forge(sh[0], 6), forge(sh[1], 6)]), throwsSsb);
      // Mixed: one honest, one forged -> equality check.
      await expectLater(Shamir.combine([sh[0], forge(sh[1], 8)]), throwsSsb);
      // Through the wire format too.
      final w = sh[1].toBytes()..[4] ^= 1;
      await expectLater(Shamir.combine([sh[0], Share.fromBytes(w)]), throwsSsb);
      expect(await Shamir.combine([sh[0], sh[1]]), secret);
    });

    test('a forged salt or keyCheck on both shares is caught by the recomputed check', () async {
      final secret = randomBytes(32);
      final sh = await Shamir.split(secret, epoch: 1);
      final salt = Uint8List.fromList(sh[0].salt)..[0] ^= 1;
      await expectLater(Shamir.combine([
        Share(2, 1, 1, salt, sh[0].keyCheck, sh[0].y),
        Share(2, 2, 1, salt, sh[1].keyCheck, sh[1].y),
      ]), throwsSsb);
      final chk = Uint8List.fromList(sh[0].keyCheck)..[15] ^= 1;
      await expectLater(Shamir.combine([
        Share(2, 1, 1, sh[0].salt, chk, sh[0].y),
        Share(2, 2, 1, sh[1].salt, chk, sh[1].y),
      ]), throwsSsb);
    });
  });

  group('Release across epochs (design D10)', () {
    late XWingKeyPair ben;
    final tk = randomBytes(32);
    const v = 'vault-1', b = 'ben-1';
    setUpAll(() async => ben = await XWing.generateKeyPair());

    Future<ReleaseBundle> make(int epoch, {Uint8List? key}) => Release.create(
        vaultId: v, beneficiaryId: b, tier: Tier.secrets,
        tierKey: key ?? tk, beneficiaryPublicKey: ben.publicKey, epoch: epoch);

    test('same epoch recovers, returns the epoch on both paths', () async {
      final k1 = await make(1);
      final online = await Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k1.beneficiaryKitCode, sealedServerShare: k1.sealedServerShare,
          beneficiarySecretKey: ben.secretKey);
      expect(online.key, tk);
      expect(online.epoch, 1);
      final offline = await Release.recoverOffline(
          beneficiaryKitCode: k1.beneficiaryKitCode, attorneyKitCode: k1.attorneyKitCode);
      expect(offline.key, tk);
      expect(offline.epoch, 1);
      // With the server's reported epoch matching, it still works.
      final withEpoch = await Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k1.beneficiaryKitCode, sealedServerShare: k1.sealedServerShare,
          beneficiarySecretKey: ben.secretKey, serverShareEpoch: 1);
      expect(withEpoch.key, tk);
    });

    test('old S1 + new S2 (same tier key, rotated epoch) fails with the older-generation message', () async {
      // The owner rotates (new epoch) but -- worst case for detection -- the
      // key bytes happen to be the same, so only the epoch differs.
      final k1 = await make(1), k2 = await make(2);
      // Server reports S2's epoch: caught before HPKE, distinct message.
      expect(await outcome(() => Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k1.beneficiaryKitCode, sealedServerShare: k2.sealedServerShare,
          beneficiarySecretKey: ben.secretKey, serverShareEpoch: 2)), 'SSB:${Release.olderGeneration}');
      // Server silent about the epoch: S2 is opened under the kit's epoch and
      // the HPKE info mismatch rejects it.
      expect(await outcome(() => Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k1.beneficiaryKitCode, sealedServerShare: k2.sealedServerShare,
          beneficiarySecretKey: ben.secretKey)), 'SSB:decrypt failed');
      // New S1 + old S2: same, both ways.
      expect(await outcome(() => Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k2.beneficiaryKitCode, sealedServerShare: k1.sealedServerShare,
          beneficiarySecretKey: ben.secretKey, serverShareEpoch: 1)), 'SSB:${Release.olderGeneration}');
      // A lying server (claims epoch 1 for an epoch-2 S2) gets 'decrypt failed', never a key.
      expect(await outcome(() => Release.recoverWithServerShare(vaultId: v, beneficiaryId: b, tier: Tier.secrets,
          beneficiaryKitCode: k1.beneficiaryKitCode, sealedServerShare: k2.sealedServerShare,
          beneficiarySecretKey: ben.secretKey, serverShareEpoch: 1)), 'SSB:decrypt failed');
    });

    test('old S1 + new S3 offline: older-generation message, in both directions', () async {
      final k1 = await make(1), k2 = await make(2);
      expect(await outcome(() => Release.recoverOffline(
          beneficiaryKitCode: k1.beneficiaryKitCode, attorneyKitCode: k2.attorneyKitCode)),
          'SSB:${Release.olderGeneration}');
      expect(await outcome(() => Release.recoverOffline(
          beneficiaryKitCode: k2.beneficiaryKitCode, attorneyKitCode: k1.attorneyKitCode)),
          'SSB:${Release.olderGeneration}');
    });

    test('kitEpoch reads the generation from S1 alone', () async {
      for (final e in [0, 1, 42, 65535]) {
        final k = await make(e);
        expect(await Release.kitEpoch(k.beneficiaryKitCode), e);
        // The label-bound checksum keeps an attorney kit out of the S1 slot.
        await expectLater(Release.kitEpoch(k.attorneyKitCode), throwsSsb);
        await expectLater(Release.kitEpoch(k.attorneyKitCode.replaceFirst('SSB2-AK', 'SSB2-BK')), throwsSsb);
      }
      await expectLater(Release.create(vaultId: v, beneficiaryId: b, tier: Tier.ice,
          tierKey: tk, beneficiaryPublicKey: ben.publicKey, epoch: 65536), throwsSsb);
      await expectLater(Release.create(vaultId: v, beneficiaryId: b, tier: Tier.ice,
          tierKey: tk, beneficiaryPublicKey: ben.publicKey, epoch: -1), throwsSsb);
    });

    test('S2 info is bound to the epoch (independent HPKE open)', () async {
      final k1 = await make(1);
      final s2 = await Hpke.open(ben.secretKey, k1.sealedServerShare,
          info: Release.s2Info(v, b, Tier.secrets, epoch: 1));
      expect(Share.fromBytes(s2).epoch, 1);
      await expectLater(Hpke.open(ben.secretKey, k1.sealedServerShare,
          info: Release.s2Info(v, b, Tier.secrets, epoch: 2)), throwsSsb);
      expect(Release.s2Info(v, b, Tier.secrets, epoch: 1),
          concatBytes([utf8Bytes('ssb/v2/s2'), lengthPrefixed(v), lengthPrefixed(b), lengthPrefixed('secrets'), [0, 1]]));
    });
  });
}
