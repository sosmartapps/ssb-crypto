@Timeout(Duration(minutes: 6))
library;

import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

import 'stress_util.dart';

void main() {
  final r = seeded(5);
  late XWingKeyPair ben, attacker;
  late Uint8List tierKey;
  late ReleaseBundle bundle;
  const vault = 'vault-1', bid = 'ben-1';

  Future<Uint8List> recover({
    String v = vault, String b = bid, Tier t = Tier.secrets, String? s1, Uint8List? s2, Uint8List? sk,
  }) =>
      Release.recoverWithServerShare(
        vaultId: v, beneficiaryId: b, tier: t,
        beneficiaryKitCode: s1 ?? bundle.beneficiaryKitCode,
        sealedServerShare: s2 ?? bundle.sealedServerShare,
        beneficiarySecretKey: sk ?? ben.secretKey,
      );

  setUpAll(() async {
    ben = await XWing.generateKeyPair();
    attacker = await XWing.generateKeyPair();
    tierKey = randomBytes(32);
    bundle = await Release.create(vaultId: vault, beneficiaryId: bid, tier: Tier.secrets,
        tierKey: tierKey, beneficiaryPublicKey: ben.publicKey);
  });

  group('release flow', () {
    test('both recovery paths return the tier key', () async {
      expect(await recover(), tierKey);
      expect(await Release.recoverOffline(
          beneficiaryKitCode: bundle.beneficiaryKitCode, attorneyKitCode: bundle.attorneyKitCode), tierKey);
    });

    test('binding of vault id, beneficiary id, tier, secret key', () async {
      final f = Fails();
      await f.mustFail('vault', () => recover(v: 'vault-2'));
      await f.mustFail('ben id', () => recover(b: 'ben-2'));
      for (final t in Tier.values.where((t) => t != Tier.secrets)) {
        await f.mustFail('tier ${t.name}', () => recover(t: t));
      }
      await f.mustFail('other sk', () => recover(sk: attacker.secretKey));
      await f.mustFail('case', () => recover(v: 'VAULT-1'));
      await f.mustFail('trailing space', () => recover(b: 'ben-1 '));
      f.done();
    });

    test('KEY SUBSTITUTION: server swaps in its own pubkey -> legit beneficiary cannot recover, attacker cannot either', () async {
      final evil = await Release.create(vaultId: vault, beneficiaryId: bid, tier: Tier.secrets,
          tierKey: tierKey, beneficiaryPublicKey: attacker.publicKey);
      final f = Fails();
      // S2 sealed to the attacker is unreadable to the real beneficiary.
      await f.mustFail('real ben opens evil S2', () => recover(s2: evil.sealedServerShare));
      // Attacker opens S2 with own key but cannot combine S2 alone or with a wrong S1.
      final s2 = Share.fromBytes(await Hpke.open(attacker.secretKey, evil.sealedServerShare,
          info: Release.s2Info(vault, bid, Tier.secrets)));
      await f.mustFail('attacker S2 alone', () => Shamir.combine([s2]));
      await f.mustFail('attacker S2 + guessed S1', () async {
        final guess = await Release.create(vaultId: vault, beneficiaryId: bid, tier: Tier.secrets,
            tierKey: randomBytes(32), beneficiaryPublicKey: attacker.publicKey);
        return Release.recoverWithServerShare(vaultId: vault, beneficiaryId: bid, tier: Tier.secrets,
            beneficiaryKitCode: guess.beneficiaryKitCode, sealedServerShare: evil.sealedServerShare,
            beneficiarySecretKey: attacker.secretKey);
      });
      f.done();
    });

    test('REPLAY: old S2 / old S1 against a rotated tier key never yields the new key', () async {
      final newKey = randomBytes(32);
      final fresh = await Release.create(vaultId: vault, beneficiaryId: bid, tier: Tier.secrets,
          tierKey: newKey, beneficiaryPublicKey: ben.publicKey);
      final f = Fails();
      await f.mustFail('old S2 + new S1', () => recover(s1: fresh.beneficiaryKitCode));
      await f.mustFail('new S2 + old S1', () => recover(s2: fresh.sealedServerShare));
      await f.mustFail('old S1 + new S3', () => Release.recoverOffline(
          beneficiaryKitCode: bundle.beneficiaryKitCode, attorneyKitCode: fresh.attorneyKitCode));
      await f.mustFail('new S1 + old S3', () => Release.recoverOffline(
          beneficiaryKitCode: fresh.beneficiaryKitCode, attorneyKitCode: bundle.attorneyKitCode));
      f.done();
      // Old material still opens only the OLD key (replay yields nothing new).
      final old = await recover();
      expect(old, tierKey);
      expect(old, isNot(newKey));
      // ...and that old key cannot open items sealed under the rotated key.
      final it = await ItemCrypto.seal(vaultId: vault, tier: Tier.secrets, tierKey: newKey, itemId: 'i', plaintext: rnd(r, 10));
      await expectLater(ItemCrypto.open(vaultId: vault, tierKey: old, item: it), throwsA(isA<SsbCryptoException>()));
    });

    test('every byte of the sealed server share (S2) is authenticated', () async {
      final f = Fails();
      for (var i = 0; i < bundle.sealedServerShare.length; i++) {
        await f.mustFail('S2 byte $i', () => recover(s2: flip(bundle.sealedServerShare, i)));
      }
      for (final n in [0, 1, 1119, 1120, 1135, 1136, bundle.sealedServerShare.length - 1]) {
        await f.mustFail('S2 trunc $n', () => recover(s2: bundle.sealedServerShare.sublist(0, n)));
      }
      await f.mustFail('S2 extend', () => recover(s2: Uint8List.fromList([...bundle.sealedServerShare, 0])));
      f.done();
    });

    test('kit codes: label confusion, any single-character change, wrong length, S1/S3 swap', () async {
      final f = Fails();
      final alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
      await f.mustFail('S3 as S1', () => recover(s1: bundle.attorneyKitCode));
      await f.mustFail('S1 as S3', () => Release.recoverOffline(
          beneficiaryKitCode: bundle.attorneyKitCode, attorneyKitCode: bundle.beneficiaryKitCode));
      await f.mustFail('S1+S1', () => Release.recoverOffline(
          beneficiaryKitCode: bundle.beneficiaryKitCode, attorneyKitCode: bundle.beneficiaryKitCode));
      await f.mustFail('recovery-key label', () => VaultKeyring.parseRecoveryKey(bundle.beneficiaryKitCode));
      await f.mustFail('secret-key label', () => Unlock.parseSecretKey(bundle.beneficiaryKitCode));
      final code = bundle.beneficiaryKitCode;
      final start = code.indexOf('-', 8) - 5 + 1; // skip label
      for (var i = Release.s1Label.length; i < code.length; i++) {
        if (code[i] == '-') continue;
        final alt = alphabet[(alphabet.indexOf(code[i]) + 1) % 32];
        final bad = code.substring(0, i) + alt + code.substring(i + 1);
        await f.mustFail('S1 char $i', () => recover(s1: bad));
      }
      expect(start, isNonNegative);
      await f.mustFail('S1 minus last char', () => recover(s1: code.substring(0, code.length - 1)));
      await f.mustFail('S1 plus char', () => recover(s1: '${code}0'));
      await f.mustFail('S1 empty', () => recover(s1: ''));
      f.done();
    });

    test('FINDING-CANDIDATE: S2 info string is unambiguous across (vaultId, beneficiaryId)', () async {
      // info = "ssb/v1/s2|vault:$v|beneficiary:$b|tier:$t" with no escaping or
      // length prefixes: ids containing the delimiters can collide.
      final b2 = await Release.create(
          vaultId: 'x|beneficiary:y', beneficiaryId: 'z', tier: Tier.ice,
          tierKey: tierKey, beneficiaryPublicKey: ben.publicKey);
      await expectLater(
          Release.recoverWithServerShare(
              vaultId: 'x', beneficiaryId: 'y|beneficiary:z', tier: Tier.ice,
              beneficiaryKitCode: b2.beneficiaryKitCode, sealedServerShare: b2.sealedServerShare,
              beneficiarySecretKey: ben.secretKey),
          throwsA(isA<SsbCryptoException>()),
          reason: 'S2 for (vault "x|beneficiary:y", ben "z") opened as (vault "x", ben "y|beneficiary:z")');
    });

    test('FINDING-CANDIDATE: item AEAD contexts are unambiguous across (vaultId, itemId)', () async {
      final tk = randomBytes(32);
      final it = await ItemCrypto.seal(vaultId: 'x|tier:ice|item:y', tier: Tier.ice, tierKey: tk, itemId: 'z', plaintext: rnd(r, 8));
      // same bytes, re-labelled with the id boundary moved
      await expectLater(
          ItemCrypto.open(vaultId: 'x', tierKey: tk, item: SealedItem('y|tier:ice|item:z', Tier.ice, it.wrappedItemKey, it.body)),
          throwsA(isA<SsbCryptoException>()),
          reason: 'item for vault "x|tier:ice|item:y"/"z" accepted as vault "x"/"y|tier:ice|item:z"');
    });
  });

  group('safety numbers', () {
    test('deterministic, 30 bytes, 12 groups of 5 digits', () async {
      final pk = ben.publicKey;
      final a = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: pk);
      final b = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: pk);
      expect(a, b);
      expect(a.length, 30);
      final d = SafetyNumber.digits(a);
      expect(RegExp(r'^(\d{5} ){11}\d{5}$').hasMatch(d), isTrue, reason: d);
    });

    test('any 1-bit change in the public key (sampled 160 positions incl. first/last bytes) changes the number', () async {
      final pk = ben.publicKey;
      final base = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: pk);
      final baseDigits = SafetyNumber.digits(base);
      final pos = <int>{0, 1, 31, 32, 1183, 1184, 1214, 1215};
      while (pos.length < 160) {
        pos.add(r.nextInt(pk.length));
      }
      final f = Fails();
      for (final i in pos) {
        final bit = r.nextInt(8);
        final fp = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: flip(pk, i, 1 << bit));
        f.check(!SafetyNumber.matches(base, fp), 'pk byte $i bit $bit same fingerprint');
        f.check(SafetyNumber.digits(fp) != baseDigits, 'pk byte $i bit $bit same digits');
      }
      f.done();
    });

    test('any 1-bit change in the beneficiary id changes the number; id/key boundary is unambiguous', () async {
      final pk = ben.publicKey;
      final base = await SafetyNumber.fingerprint(beneficiaryId: 'ben-1', publicKey: pk);
      final f = Fails();
      final idb = utf8Bytes('ben-1');
      for (var i = 0; i < idb.length; i++) {
        for (var bit = 0; bit < 8; bit++) {
          final id2 = String.fromCharCodes(flip(idb, i, 1 << bit));
          final fp = await SafetyNumber.fingerprint(beneficiaryId: id2, publicKey: pk);
          f.check(!SafetyNumber.matches(base, fp), 'id byte $i bit $bit');
        }
      }
      // shift a byte between id and key
      final fa = await SafetyNumber.fingerprint(beneficiaryId: 'ab', publicKey: Uint8List.fromList([99, ...pk]));
      final fb = await SafetyNumber.fingerprint(beneficiaryId: 'abc', publicKey: pk);
      f.check(!SafetyNumber.matches(fa, fb), 'boundary shift');
      // truncated / extended / reversed keys
      for (final k in [pk.sublist(0, pk.length - 1), Uint8List.fromList([...pk, 0]), Uint8List(0), Uint8List.fromList(pk.reversed.toList())]) {
        f.check(!SafetyNumber.matches(base, await SafetyNumber.fingerprint(beneficiaryId: 'ben-1', publicKey: k)), 'len ${k.length}');
      }
      f.done();
    });

    test('key substitution: attacker key never matches; 100 random keys give 100 distinct numbers', () async {
      final real = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: ben.publicKey);
      final evil = await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: attacker.publicKey);
      expect(SafetyNumber.matches(real, evil), isFalse);
      expect(SafetyNumber.digits(real), isNot(SafetyNumber.digits(evil)));
      expect(SafetyNumber.matches(real, real.sublist(0, 29)), isFalse);
      final seen = <String>{};
      for (var i = 0; i < 100; i++) {
        seen.add(SafetyNumber.digits(await SafetyNumber.fingerprint(beneficiaryId: bid, publicKey: rnd(r, 1216))));
      }
      expect(seen.length, 100);
    });
  });

  group('claim / owner tokens', () {
    test('deterministic, domain separated, verifier != token, every key byte matters', () async {
      final sk = rnd(r, 32);
      final t = await ClaimToken.compute(beneficiarySecretKey: sk);
      expect(await ClaimToken.compute(beneficiarySecretKey: sk), t);
      expect(t.length, 128);
      final v = await ClaimToken.verifier(t);
      expect(v, isNot(t));
      expect(await ClaimToken.verifier(t), v);
      final f = Fails();
      for (var i = 0; i < sk.length; i++) {
        f.check(await ClaimToken.compute(beneficiarySecretKey: flip(sk, i)) != t, 'claim sk byte $i');
      }
      // claim vs owner tokens with identical inputs differ
      final o = await OwnerToken.compute(vaultId: '', vaultKey: sk);
      f.check(o != t, 'claim==owner');
      f.check(await OwnerToken.compute(vaultId: 'a', vaultKey: sk) != await OwnerToken.compute(vaultId: 'b', vaultKey: sk), 'owner vault id');
      f.check(await OwnerToken.compute(vaultId: 'a', vaultKey: Uint8List.fromList([...sk, 1])) !=
          await OwnerToken.compute(vaultId: 'a1', vaultKey: sk), 'owner boundary');
      f.check(await OwnerToken.compute(vaultId: 'ab', vaultKey: sk) != await OwnerToken.compute(vaultId: 'a', vaultKey: Uint8List.fromList([0x62, ...sk])), 'owner boundary 2');
      f.check(await OwnerToken.verifier(o) != o, 'owner verifier');
      f.done();
    });

    test('FINDING-CANDIDATE: claim token refuses a malformed (empty / short) secret key', () async {
      final f = Fails();
      for (final n in [0, 1, 16]) {
        await f.mustFail('claim sk len $n', () => ClaimToken.compute(beneficiarySecretKey: Uint8List(n)));
      }
      f.done();
    });
  });
}
