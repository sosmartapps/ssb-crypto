import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';
import 'package:test/test.dart';

Matcher get throwsSsb => throwsA(isA<SsbCryptoException>());

/// Fixed inputs so the derived keys below are known-answer vectors.
final _sk = Uint8List.fromList(List.generate(16, (i) => i));
final _salt = Uint8List.fromList(List.generate(16, (i) => 16 + i));

Future<String> _derive(String p, {bool normalize = true}) async => hexEncode(
    await Unlock.deriveUnlockKey(
        passphrase: p,
        secretKey: _sk,
        accountSalt: _salt,
        params: Argon2Params.testOnly,
        normalize: normalize));

const _composed = 'café crème'; // precomposed é / è
const _decomposed = 'café crème'; // e + combining accents

void main() {
  group('NFKD normalization', () {
    test('canonical and compatibility forms collapse', () {
      expect(Unlock.normalizePassphrase(_composed), _decomposed);
      expect(Unlock.normalizePassphrase(_decomposed), _decomposed);
      // Full-width Latin (CJK keyboards), no-break space, "ﬁ" ligature.
      expect(Unlock.normalizePassphrase('ｐａｓｓ ﬁle'),
          'pass file');
      expect(Unlock.normalizePassphrase('correct horse'), 'correct horse');
    });

    test('hasLegacyForm only for passphrases NFKD changes', () {
      expect(Unlock.hasLegacyForm('correct horse battery staple'), isFalse);
      expect(Unlock.hasLegacyForm(_decomposed), isFalse);
      expect(Unlock.hasLegacyForm(_composed), isTrue);
      expect(Unlock.hasLegacyForm('ｐａｓｓ'), isTrue);
    });
  });

  group('Unlock Key known-answer vectors (Argon2Params.testOnly)', () {
    const asciiKey =
        '660ac45e8c1a9cbadb5c7d7d8420a9d5265224b2e0a13dde89eb4fb8351d18af';
    const cafeNormalized =
        '6e7fb45e1212f267f5305d1feaeed010c1cde2aaa3b19c0014da25900f022ade';
    const cafeLegacyRaw =
        'fd3a32e75af9df316018b93573402cbf3f4d6e9855a1812babf93113749b8921';

    test('ASCII passphrase derives the same key as before normalization', () async {
      expect(await _derive('correct horse battery staple'), asciiKey);
      expect(await _derive('correct horse battery staple', normalize: false), asciiKey);
    });

    test('composed and decomposed input derive one key', () async {
      expect(await _derive(_composed), cafeNormalized);
      expect(await _derive(_decomposed), cafeNormalized);
      expect(await _derive(_decomposed, normalize: false), cafeNormalized);
    });

    test('legacy raw derivation of the composed form is distinct', () async {
      expect(await _derive(_composed, normalize: false), cafeLegacyRaw);
    });
  });

  group('openWithPassphrase', () {
    Future<Uint8List> kek(String p, {bool normalize = true}) =>
        Unlock.deriveUnlockKey(
            passphrase: p,
            secretKey: _sk,
            accountSalt: _salt,
            params: Argon2Params.testOnly,
            normalize: normalize);

    /// Seals a fresh keyring's Vault Key under [p]; returns an opener.
    /// (VaultKeyring.open requires every tier's wrapped key -- Phase 0, B2.)
    final anchor = InMemoryAnchor();
    Future<({String vaultId, Uint8List wrapped, Map<String, int> slotEpochs, Uint8List manifest,
        Map<Tier, Uint8List> tiers, Uint8List vaultKey})> seal(
        String p, {bool legacy = false}) async {
      final ring = VaultKeyring.create('vault-nfkd-test', anchor: anchor);
      final k = await kek(p, normalize: !legacy);
      final wrapped = await ring.wrapVaultKey(k, slot: 'unlock', epoch: 1);
      final tiers = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
      final manifest = await ring.sealManifest(items: const []);
      return (
        vaultId: ring.vaultId,
        wrapped: wrapped,
        slotEpochs: Map.of(ring.slotEpochs),
        manifest: manifest,
        tiers: tiers,
        vaultKey: Uint8List.fromList(ring.vaultKey),
      );
    }

    Future<VaultKeyring> openAs(String p,
        ({String vaultId, Uint8List wrapped, Map<String, int> slotEpochs, Uint8List manifest,
            Map<Tier, Uint8List> tiers, Uint8List vaultKey}) v,
        {List<int>? attempts}) {
      return Unlock.openWithPassphrase(
        passphrase: p,
        secretKey: _sk,
        accountSalt: _salt,
        params: Argon2Params.testOnly,
        open: (k) {
          attempts?.add(1);
          return VaultKeyring.open(
              vaultId: v.vaultId,
              kek: k,
              slot: 'unlock',
              wrappedVaultKey: v.wrapped,
              slotEpochs: v.slotEpochs,
              manifestBlob: v.manifest,
              wrappedTierKeys: v.tiers,
              items: const [],
              anchor: anchor);
        },
      );
    }

    test('new vaults open from either Unicode form, in one attempt', () async {
      final v = await seal(_composed);
      final tries = <int>[];
      expect((await openAs(_decomposed, v, attempts: tries)).vaultKey, v.vaultKey);
      expect(tries.length, 1);
      expect((await openAs(_composed, v)).vaultKey, v.vaultKey);
    });

    test('a non-key failure (corrupt manifest) does not pay a second Argon2id', () async {
      final v = await seal(_composed, legacy: false);
      final bad = Uint8List.fromList(v.manifest)..[v.manifest.length - 1] ^= 1;
      final tries = <int>[];
      await expectLater(
          Unlock.openWithPassphrase(
            passphrase: _composed,
            secretKey: _sk,
            accountSalt: _salt,
            params: Argon2Params.testOnly,
            open: (k) {
              tries.add(1);
              return VaultKeyring.open(
                  vaultId: v.vaultId, kek: k, slot: 'unlock', wrappedVaultKey: v.wrapped,
                  slotEpochs: v.slotEpochs, manifestBlob: bad, wrappedTierKeys: v.tiers,
                  items: const [], anchor: anchor);
            },
          ),
          throwsA(isA<SsbCryptoException>()));
      expect(tries.length, 1);
    });

    test('a wrong passphrase still tries the legacy form once (2 attempts)', () async {
      final v = await seal(_composed);
      final tries = <int>[];
      await expectLater(openAs('café wrong', v, attempts: tries), throwsA(isA<SsbCryptoException>()));
      expect(tries.length, 2);
    });

    test('pre-normalization vault still opens via the raw fallback', () async {
      final v = await seal(_composed, legacy: true);
      final tries = <int>[];
      expect((await openAs(_composed, v, attempts: tries)).vaultKey, v.vaultKey);
      expect(tries.length, 2);
    });

    test('wrong passphrase still fails (with and without a legacy form)', () async {
      final v = await seal('correct horse battery staple');
      final tries = <int>[];
      await expectLater(openAs('correct horse battery stapl', v, attempts: tries), throwsSsb);
      expect(tries.length, 1, reason: 'no second Argon2id for ASCII input');
      await expectLater(openAs(_composed, v), throwsSsb);
    });
  });
}
