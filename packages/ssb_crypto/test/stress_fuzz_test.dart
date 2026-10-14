@Timeout(Duration(minutes: 6))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

void main() {
  final r = seeded(6);
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  String rndCode(String label, int len) =>
      '$label-${List.generate(len, (_) => alphabet[r.nextInt(32)]).join()}';

  group('fuzz: parsers / decoders throw typed errors on garbage', () {
    test('Share.fromBytes: random lengths/bytes; success only for structurally valid input', () async {
      final f = Fails();
      for (var i = 0; i < 3000; i++) {
        final b = rnd(r, r.nextInt(80));
        final valid = b.length >= 12 && b[0] == 1 && b[1] >= 2 && b[2] != 0;
        try {
          final s = Share.fromBytes(b);
          f.check(valid, 'accepted structurally invalid share ${hexEncode(b)}');
          f.check(constantTimeEquals(s.toBytes(), b), 'share does not round trip');
        } on SsbCryptoException {
          f.check(!valid, 'rejected valid share');
        } catch (e) {
          f.add('Share.fromBytes WRONG-ERROR ${e.runtimeType}');
        }
      }
      f.done();
    });

    test('Shamir.combine on random structurally-valid shares always rejects', () async {
      final f = Fails();
      for (var i = 0; i < 300; i++) {
        final len = 1 + r.nextInt(40);
        final a = Share(2, 1 + r.nextInt(3), rnd(r, 8), rnd(r, len));
        final b = Share(2, 1 + r.nextInt(3), a.keyCheck, rnd(r, len));
        await f.mustFail('random shares', () => Shamir.combine([a, b]));
      }
      f.done();
    });

    test('KitCode.decode (via Unlock/Recovery/Release entry points): random + hostile strings', () async {
      final f = Fails();
      final hostile = <String>[
        '', ' ', '-', '----', 'SSB1', 'SSB1-', 'SSB1-SK', 'SSB1-SK-', '\u0000', 'SSB1-SK-\u0000\u0000',
        'ＳＳＢ１－ＳＫ', 'SSB1-SK-' + 'U' * 30, 'SSB1-SK-' + 'I' * 30, 'ssb1-sk-' + '0' * 30,
        'SSB1-SK-\u{1F600}' * 3, 'A' * 1000000, 'SSB1-SK-' + 'Z' * 1000000, '\n' * 10000,
      ];
      for (final h in hostile) {
        await f.mustFail('SK hostile ${h.length}', () => Unlock.parseSecretKey(h));
        await f.mustFail('RK hostile ${h.length}', () => VaultKeyring.parseRecoveryKey(h));
        await f.mustFail('S1 hostile ${h.length}', () => Release.recoverOffline(beneficiaryKitCode: h, attorneyKitCode: h));
      }
      for (var i = 0; i < 2000; i++) {
        final len = [0, 1, 5, 10, 26, 27, 28, 30, 40, 52, 53, 54, 58, 60, 80, 200][r.nextInt(16)];
        await f.mustFail('rnd SK len $len', () => Unlock.parseSecretKey(rndCode('SSB1-SK', len)));
        await f.mustFail('rnd RK len $len', () => VaultKeyring.parseRecoveryKey(rndCode('SSB1-RK', len)));
      }
      // exact right length, random chars: checksum must reject
      for (var i = 0; i < 1000; i++) {
        await f.mustFail('SK exact len', () => Unlock.parseSecretKey(rndCode('SSB1-SK', 32))); // (16+4)*8/5
        await f.mustFail('RK exact len', () => VaultKeyring.parseRecoveryKey(rndCode('SSB1-RK', 58))); // (32+4)*8/5=57.6->58
      }
      f.done();
    });

    test('KitCode round trip survives forgiving decode; non-canonical trailing bits rejected', () async {
      final sk = Unlock.newSecretKey();
      final code = await Unlock.formatSecretKey(sk);
      expect(await Unlock.parseSecretKey(code), sk);
      expect(await Unlock.parseSecretKey(code.toLowerCase().replaceAll('-', ' ')), sk);
      final f = Fails();
      for (var i = 7; i < code.length; i++) {
        if (code[i] == '-') continue;
        for (final ch in alphabet.split('')) {
          if (ch == code[i]) continue;
          final bad = code.substring(0, i) + ch + code.substring(i + 1);
          try {
            final out = await Unlock.parseSecretKey(bad);
            f.add('accepted modified code at $i -> $ch, equal=${constantTimeEquals(out, sk)}');
          } on SsbCryptoException {
          } catch (e) {
            f.add('WRONG-ERROR ${e.runtimeType}');
          }
        }
      }
      f.done();
    });

    test('hexDecode: odd length / non-hex throw FormatException (typed), never garbage', () {
      for (final s in ['a', 'abc', 'zz', 'g0', '0x', '--', 'éé', '+1', ' 1']) {
        expect(() => hexDecode(s), throwsFormatException, reason: s);
      }
      expect(hexDecode(''), isEmpty);
    });
  });

  group('fuzz: decrypt entry points reject random bytes', () {
    final key = randomBytes(32);

    test('Aead.open: random blobs of random length, and with a valid header prefix', () async {
      final hdr = buildHeader(ObjectType.item);
      final f = Fails();
      for (var i = 0; i < 4000; i++) {
        final n = r.nextInt(120);
        final b = rnd(r, n);
        await f.mustFail('rnd $n', () => Aead.open(key, b, type: ObjectType.item));
        if (n >= 6) {
          final c = Uint8List.fromList(b)..setRange(0, 6, hdr);
          await f.mustFail('hdr $n', () => Aead.open(key, c, type: ObjectType.item));
        }
      }
      f.done();
    });

    test('StreamCipher.decrypt: random + valid header with hostile chunk sizes', () async {
      final hdr = buildHeader(ObjectType.fileStream);
      final f = Fails();
      for (var i = 0; i < 2000; i++) {
        final b = rnd(r, r.nextInt(200));
        await f.mustFail('rnd', () => StreamCipher.decrypt(key, b));
        if (b.length >= 17) {
          final c = Uint8List.fromList(b)..setRange(0, 6, hdr);
          await f.mustFail('hdr', () => StreamCipher.decrypt(key, c));
        }
      }
      for (final cs in [0, 1, 16, 65536, 16 * 1024 * 1024, 16 * 1024 * 1024 + 1, 0x7fffffff, 0xffffffff]) {
        for (final tail in [16, 17, 100, 70000]) {
          final c = Uint8List.fromList([...hdr, ...rnd(r, 7), ...u32be(cs), ...rnd(r, tail)]);
          await f.mustFail('cs=$cs tail=$tail', () => StreamCipher.decrypt(key, c));
        }
      }
      f.done();
    });

    test('Hpke.open: random lengths around enc size; X-Wing decapsulate never returns for wrong sizes', () async {
      final kp = await XWing.generateKeyPair();
      final f = Fails();
      for (var i = 0; i < 300; i++) {
        final n = [0, 1, 15, 16, 17, 1119, 1120, 1135, 1136, 1137, 1200, 2000][r.nextInt(12)];
        await f.mustFail('hpke rnd $n', () => Hpke.open(kp.secretKey, rnd(r, n)));
      }
      for (final n in [0, 1, 1088, 1119, 1121, 4096]) {
        await f.mustFail('decaps ct len $n', () => XWing.decapsulate(rnd(r, n), kp.secretKey));
      }
      // right length, random bytes: implicit rejection => returns 32 bytes (must not crash/hang)
      for (var i = 0; i < 100; i++) {
        final ss = await XWing.decapsulate(rnd(r, 1120), kp.secretKey);
        f.check(ss.length == 32, 'decaps random ct len');
      }
      f.done();
    });

    test('HybridSignature.verify: random garbage never verifies, never throws non-typed', () async {
      final kp = await HybridSignature.generateKeyPair();
      var ok = 0;
      for (var i = 0; i < 100; i++) {
        try {
          if (await HybridSignature.verify(kp.publicKey, rnd(r, r.nextInt(50)), rnd(r, HybridSignature.signatureLength), purpose: 'x')) ok++;
        } on SsbCryptoException {
        }
      }
      expect(ok, 0);
      for (final n in [0, 1, 64, 3372, 3374]) {
        try {
          expect(await HybridSignature.verify(kp.publicKey, Uint8List(1), rnd(r, n), purpose: 'x'), isFalse);
        } on SsbCryptoException {
        }
      }
    });

    test('VaultKeyring.open / fromVaultKey / ItemCrypto.open / openFile with junk', () async {
      final f = Fails();
      for (var i = 0; i < 300; i++) {
        final junk = rnd(r, r.nextInt(150));
        await f.mustFail('ring', () => VaultKeyring.open(vaultId: 'V', kek: key, slot: 'unlock', wrappedVaultKey: junk, wrappedTierKeys: {}));
        await f.mustFail('fromVaultKey', () => VaultKeyring.fromVaultKey(vaultId: 'V', vaultKey: key, wrappedTierKeys: {Tier.ice: junk}));
        await f.mustFail('item', () => ItemCrypto.open(vaultId: 'V', tierKey: key, item: SealedItem('i', Tier.ice, junk, junk)));
        await f.mustFail('file', () => ItemCrypto.openFile(vaultId: 'V', tier: Tier.ice, tierKey: key, fileId: 'f', wrappedKey: junk, stream: junk));
      }
      f.done();
    });

    test('Release.recover*: junk codes/shares/keys all typed errors', () async {
      final kp = await XWing.generateKeyPair();
      final f = Fails();
      for (var i = 0; i < 200; i++) {
        await f.mustFail('server', () => Release.recoverWithServerShare(
            vaultId: 'V', beneficiaryId: 'B', tier: Tier.ice,
            beneficiaryKitCode: rndCode('SSB1-BK', r.nextInt(100)),
            sealedServerShare: rnd(r, r.nextInt(1300)),
            beneficiarySecretKey: kp.secretKey));
        await f.mustFail('offline', () => Release.recoverOffline(
            beneficiaryKitCode: rndCode('SSB1-BK', 70), attorneyKitCode: rndCode('SSB1-AK', 70)));
      }
      await f.mustFail('create pk len', () => Release.create(vaultId: 'V', beneficiaryId: 'B', tier: Tier.ice,
          tierKey: randomBytes(32), beneficiaryPublicKey: Uint8List(10)));
      await f.mustFail('create empty tier key', () => Release.create(vaultId: 'V', beneficiaryId: 'B', tier: Tier.ice,
          tierKey: Uint8List(0), beneficiaryPublicKey: kp.publicKey));
      f.done();
    });

    test('Unlock.deriveUnlockKey rejects bad secret-key / salt lengths', () async {
      final f = Fails();
      for (final (sk, salt) in [(0, 16), (15, 16), (17, 16), (16, 0), (16, 15), (16, 17), (32, 32)]) {
        await f.mustFail('sk $sk salt $salt', () => Unlock.deriveUnlockKey(
            passphrase: 'pw', secretKey: Uint8List(sk), accountSalt: Uint8List(salt), params: Argon2Params.testOnly));
      }
      f.done();
    });
  });
}
