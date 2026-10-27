// SSB-2026-002 Phase 1 (M2/M4): Share v2 wire format and Kit v2 codes.
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

final Matcher throwsSsb = throwsA(isA<SsbCryptoException>());

void main() {
  group('Share v2 layout (design D2)', () {
    test('a 32-byte secret gives a 61-byte share: version 2 | threshold | x | epoch u16 | salt 8 | keyCheck 16 | y 32', () async {
      final secret = randomBytes(32);
      final sh = await Shamir.split(secret, epoch: 0x0102);
      for (final s in sh) {
        final w = s.toBytes();
        expect(w.length, 61);
        expect(Share.headerLength, 29);
        expect(w[0], 2);
        expect(w[1], 2);
        expect(w[2], s.x);
        expect(w.sublist(3, 5), [0x01, 0x02]);
        expect(w.sublist(5, 13), s.salt);
        expect(w.sublist(13, 29), s.keyCheck);
        expect(w.sublist(29), s.y);
        expect(s.salt.length, 8);
        expect(s.keyCheck.length, 16);
        expect(s.epoch, 0x0102);
        final back = Share.fromBytes(w);
        expect(back.toBytes(), w);
        expect(back.epoch, 0x0102);
      }
      expect(await Shamir.combine([sh[0], sh[2]]), secret);
    });

    test('all three shares of one split share salt, keyCheck and epoch', () async {
      final sh = await Shamir.split(randomBytes(32), epoch: 5);
      expect(sh[1].salt, sh[0].salt);
      expect(sh[2].salt, sh[0].salt);
      expect(sh[1].keyCheck, sh[0].keyCheck);
      expect(sh[2].keyCheck, sh[0].keyCheck);
      expect(sh.map((s) => s.epoch).toSet(), {5});
    });

    test('two independent splits of the SAME secret give different salts and keyChecks (B5)', () async {
      final secret = randomBytes(32);
      final a = await Shamir.split(secret, epoch: 1);
      final b = await Shamir.split(secret, epoch: 1);
      expect(a[0].salt, isNot(b[0].salt));
      expect(a[0].keyCheck, isNot(b[0].keyCheck));
      // Same secret, same epoch, same salt forced -> same check (the check is a function of all three).
      expect(a[0].keyCheck, a[1].keyCheck);
    });

    test('combining shares from two splits of the same secret fails', () async {
      final secret = randomBytes(32);
      final a = await Shamir.split(secret, epoch: 1);
      final b = await Shamir.split(secret, epoch: 1);
      await expectLater(Shamir.combine([a[0], b[1]]), throwsSsb);
      await expectLater(Shamir.combine([b[0], a[1]]), throwsSsb);
      await expectLater(Shamir.combine([a[0], a[1], b[2]]), throwsSsb);
      // ...and of course each split still works on its own.
      expect(await Shamir.combine([a[0], a[1]]), secret);
      expect(await Shamir.combine([b[1], b[2]]), secret);
    });

    test('v1 shares (43 bytes, version byte 1) are refused by Share.fromBytes', () {
      final v1 = Uint8List.fromList([1, 2, 1, ...List.filled(8, 7), ...List.filled(32, 9)]);
      expect(v1.length, 43);
      expect(() => Share.fromBytes(v1), throwsSsb);
      // A v1 share padded to 61 bytes is still version 1 -> refused.
      expect(() => Share.fromBytes(Uint8List.fromList([...v1, ...List.filled(18, 0)])), throwsSsb);
      // Flipping just the version byte of a v1 share yields a structurally
      // v2-looking share with garbage fields; it parses but cannot combine.
      final flipped = Uint8List.fromList([...v1, ...List.filled(18, 0)])..[0] = 2;
      final s = Share.fromBytes(flipped);
      expect(() => Shamir.combine([s, s]), throwsSsb);
    });

    test('epoch range: 0 and 65535 split; negatives and 65536 are refused', () async {
      expect((await Shamir.split(randomBytes(32), epoch: 0))[0].epoch, 0);
      expect((await Shamir.split(randomBytes(32), epoch: Share.maxEpoch))[0].epoch, 0xffff);
      await expectLater(Shamir.split(randomBytes(32), epoch: -1), throwsSsb);
      await expectLater(Shamir.split(randomBytes(32), epoch: 0x10000), throwsSsb);
    });
  });

  group('Kit v2 codes (design D3)', () {
    late XWingKeyPair ben;
    setUpAll(() async => ben = await XWing.generateKeyPair());

    test('labels SSB2-BK / SSB2-AK and a 61-byte payload: (61+4)*8/5 = 104 base32 chars', () async {
      final b = await Release.create(vaultId: 'v', beneficiaryId: 'b', tier: Tier.secrets,
          tierKey: randomBytes(32), beneficiaryPublicKey: ben.publicKey, epoch: 3);
      expect(b.beneficiaryKitCode, startsWith('SSB2-BK-'));
      expect(b.attorneyKitCode, startsWith('SSB2-AK-'));
      expect(b.epoch, 3);
      String digits(String code) => code.substring(8).replaceAll('-', '');
      expect(digits(b.beneficiaryKitCode).length, 104);
      expect(digits(b.attorneyKitCode).length, 104);
      // 5-char groups: 20 full + one of 4.
      expect(b.beneficiaryKitCode.split('-').length, 2 + 21);
      expect(await Release.kitEpoch(b.beneficiaryKitCode), 3);
    });

    test('a v1-labelled kit is refused everywhere a v2 kit is expected', () async {
      final b = await Release.create(vaultId: 'v', beneficiaryId: 'b', tier: Tier.ice,
          tierKey: randomBytes(32), beneficiaryPublicKey: ben.publicKey, epoch: 1);
      final asV1 = b.beneficiaryKitCode.replaceFirst('SSB2-BK', 'SSB1-BK');
      await expectLater(Release.kitEpoch(asV1), throwsSsb);
      await expectLater(Release.recoverOffline(beneficiaryKitCode: asV1, attorneyKitCode: b.attorneyKitCode), throwsSsb);
      await expectLater(Release.recoverWithServerShare(vaultId: 'v', beneficiaryId: 'b', tier: Tier.ice,
          beneficiaryKitCode: asV1, sealedServerShare: b.sealedServerShare, beneficiarySecretKey: ben.secretKey), throwsSsb);
      // A genuine v1-length code (43+4 bytes -> 76 chars) under the v2 label is the wrong length.
      final v1Len = 'SSB2-BK-${List.filled(76, 'A').join()}';
      await expectLater(Release.kitEpoch(v1Len), throwsSsb);
    });
  });
}
