/// Format-v1 READ paths (pre SSB-2026-002), kept verbatim so vaults sealed
/// before Phase 1 can be opened ONCE and migrated to format v2.
///
/// Import only via `package:ssb_crypto/legacy_v1.dart`, and only from the
/// migration (`vault_migration.dart`) and the transitional claim path for
/// beneficiaries whose owner has not migrated yet. Nothing here seals
/// anything: v1 objects are read, their contents re-sealed with the v2 API,
/// and the v1 objects discarded. None of these contexts carry an epoch, so
/// none of them can tell a current object from a replayed one -- that is the
/// finding this package version fixes.
library;

import 'dart:typed_data';

import 'aead.dart';
import 'bytes.dart';
import 'hpke.dart';
import 'kdf.dart';
import 'kit_code.dart';
import 'stream.dart';
import 'suite.dart';
import 'vault.dart';

// ---------------------------------------------------------------------------
// Shamir v1
// ---------------------------------------------------------------------------

/// A v1 share: version(1)=1 | threshold(1) | x(1) | keyCheck(8) | y.
/// keyCheck = HKDF(secret, salt='', 'ssb/v1/share-check')[0..8], unsalted.
class ShareV1 {
  static const version = 1;
  final int threshold;
  final int x;
  final Uint8List keyCheck;
  final Uint8List y;
  ShareV1(this.threshold, this.x, this.keyCheck, this.y);

  factory ShareV1.fromBytes(Uint8List b) {
    if (b.length < 3 + 8 + 1 || b[0] != version || b[1] < 2 || b[2] == 0) {
      throw const SsbCryptoException('invalid share');
    }
    return ShareV1(b[1], b[2], Uint8List.fromList(b.sublist(3, 11)),
        Uint8List.fromList(b.sublist(11)));
  }

  void erase() => wipe(y);
}

/// v1 `Shamir.combine`, verbatim (field arithmetic duplicated on purpose so
/// this file has no dependency on the live implementation's internals).
abstract final class ShamirV1 {
  static Future<Uint8List> combine(List<ShareV1> shares) async {
    if (shares.isEmpty) throw const SsbCryptoException('not enough shares');
    final k = shares.first.threshold;
    final len = shares.first.y.length;
    final byX = <int, ShareV1>{};
    for (final s in shares) {
      if (s.threshold != k || s.y.length != len || s.x < 1 || s.x > 255 ||
          !constantTimeEquals(s.keyCheck, shares.first.keyCheck)) {
        throw const SsbCryptoException('shares do not match');
      }
      final prev = byX[s.x];
      if (prev == null) {
        byX[s.x] = s;
      } else if (!constantTimeEquals(prev.y, s.y)) {
        throw const SsbCryptoException('shares do not match');
      }
    }
    if (byX.length < k) throw const SsbCryptoException('not enough shares');
    final use = byX.values.take(k).toList();
    final out = Uint8List(len);
    for (var i = 0; i < len; i++) {
      var acc = 0;
      for (var a = 0; a < k; a++) {
        var num = 1, den = 1;
        for (var b = 0; b < k; b++) {
          if (a == b) continue;
          num = _mul(num, use[b].x);
          den = _mul(den, use[b].x ^ use[a].x);
        }
        acc ^= _mul(use[a].y[i], _mul(num, _inv(den)));
      }
      out[i] = acc;
    }
    if (!constantTimeEquals(await _keyCheck(out), shares.first.keyCheck)) {
      wipe(out);
      throw const SsbCryptoException('shares do not match');
    }
    return out;
  }

  static Future<Uint8List> _keyCheck(Uint8List secret) =>
      hkdfSha384(ikm: secret, salt: const [], info: 'ssb/v1/share-check', length: 8);

  static int _mul(int a, int b) {
    var p = 0;
    for (var i = 0; i < 8; i++) {
      p ^= a & -(b & 1);
      final hi = -((a >> 7) & 1);
      a = ((a << 1) ^ (0x1b & hi)) & 0xff;
      b >>= 1;
    }
    return p & 0xff;
  }

  static int _inv(int a) {
    var r = 1, base = a;
    for (var e = 254; e > 0; e >>= 1) {
      if (e & 1 == 1) r = _mul(r, base);
      base = _mul(base, base);
    }
    return r;
  }
}

// ---------------------------------------------------------------------------
// Release v1 (kits SSB1-BK / SSB1-AK, 43-byte shares, S2 info without epoch)
// ---------------------------------------------------------------------------

abstract final class ReleaseV1 {
  static const s1Label = 'SSB1-BK';
  static const s3Label = 'SSB1-AK';
  static const _shareLen = 3 + 8 + 32;

  static List<int> s2Info(String vaultId, String beneficiaryId, Tier t) => concatBytes([
        utf8Bytes('ssb/v2/s2'),
        lengthPrefixed(vaultId),
        lengthPrefixed(beneficiaryId),
        lengthPrefixed(t.name),
      ]);

  /// v1 Beneficiary Kit + v1 server share. Returns the (v1, epoch-less)
  /// tier key; the caller should treat it as generation 0.
  static Future<Uint8List> recoverWithServerShare({
    required String vaultId,
    required String beneficiaryId,
    required Tier tier,
    required String beneficiaryKitCode,
    required Uint8List sealedServerShare,
    required Uint8List beneficiarySecretKey,
  }) async {
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw2;
    ShareV1? s1, s2;
    try {
      s1 = ShareV1.fromBytes(raw1);
      raw2 = await Hpke.open(beneficiarySecretKey, sealedServerShare,
          info: s2Info(vaultId, beneficiaryId, tier));
      s2 = ShareV1.fromBytes(raw2);
      return await ShamirV1.combine([s1, s2]);
    } finally {
      wipe(raw1);
      wipe(raw2);
      s1?.erase();
      s2?.erase();
    }
  }

  /// v1 Beneficiary Kit + v1 attorney kit, offline.
  static Future<Uint8List> recoverOffline({
    required String beneficiaryKitCode,
    required String attorneyKitCode,
  }) async {
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw3;
    ShareV1? s1, s3;
    try {
      s1 = ShareV1.fromBytes(raw1);
      raw3 = await KitCode.decode(s3Label, attorneyKitCode, payloadLength: _shareLen);
      s3 = ShareV1.fromBytes(raw3);
      return await ShamirV1.combine([s1, s3]);
    } finally {
      wipe(raw1);
      wipe(raw3);
      s1?.erase();
      s3?.erase();
    }
  }
}

// ---------------------------------------------------------------------------
// Keyring v1
// ---------------------------------------------------------------------------

/// The keys a v1 vault file yields: enough to read its items and to build a
/// v2 [VaultKeyring] with [VaultKeyring.adopt]. Has no manifest, epochs or
/// anchor -- it must not be used for anything but the migration.
class LegacyKeyring {
  final String vaultId;
  final Uint8List vaultKey;
  final Map<Tier, Uint8List> tierKeys;
  LegacyKeyring(this.vaultId, this.vaultKey, this.tierKeys);

  Uint8List tierKey(Tier t) {
    final k = tierKeys[t];
    if (k == null) throw const SsbCryptoException('missing tier key');
    return k;
  }

  void dispose() {
    wipe(vaultKey);
    tierKeys.values.forEach(wipe);
  }
}

/// v1 `VaultKeyring.open` / `fromVaultKey`, verbatim: contexts
/// `ssb/v1/vk/<slot>|vault:<id>` and `ssb/v1/tk/<tier>|vault:<id>`, header
/// version byte 1, no epochs, no manifest. Fails closed on a partial tier
/// map (Phase 0, B2).
abstract final class VaultKeyringV1 {
  static List<int> vkContext(String vaultId, String slot) =>
      VaultKeyring.legacyVkContext(vaultId, slot);
  static List<int> tkContext(String vaultId, Tier t) =>
      utf8Bytes('ssb/v1/tk/${t.name}|vault:$vaultId');

  static void _requireAllTiers(Map<Tier, Uint8List> wrapped) {
    for (final t in Tier.values) {
      if (!wrapped.containsKey(t)) throw const SsbCryptoException('missing tier key');
    }
  }

  static Future<LegacyKeyring> open({
    required String vaultId,
    required Uint8List kek,
    required String slot,
    required Uint8List wrappedVaultKey,
    required Map<Tier, Uint8List> wrappedTierKeys,
  }) async {
    _requireAllTiers(wrappedTierKeys);
    final vk = await Aead.openLegacyV1(kek, wrappedVaultKey,
        type: ObjectType.wrappedKey, context: vkContext(vaultId, slot));
    return _tiers(vaultId, vk, wrappedTierKeys);
  }

  static Future<LegacyKeyring> fromVaultKey({
    required String vaultId,
    required Uint8List vaultKey,
    required Map<Tier, Uint8List> wrappedTierKeys,
  }) async {
    if (vaultKey.length != Aead.keyLength || isAllZero(vaultKey)) {
      throw const SsbCryptoException('bad vault key');
    }
    _requireAllTiers(wrappedTierKeys);
    return _tiers(vaultId, Uint8List.fromList(vaultKey), wrappedTierKeys);
  }

  static Future<LegacyKeyring> _tiers(
      String vaultId, Uint8List vk, Map<Tier, Uint8List> wrapped) async {
    final tks = <Tier, Uint8List>{};
    try {
      for (final e in wrapped.entries) {
        tks[e.key] = await Aead.openLegacyV1(vk, e.value,
            type: ObjectType.wrappedKey, context: tkContext(vaultId, e.key));
      }
    } catch (_) {
      wipe(vk);
      tks.values.forEach(wipe);
      rethrow;
    }
    return LegacyKeyring(vaultId, vk, tks);
  }
}

// ---------------------------------------------------------------------------
// Items / files / tier export v1
// ---------------------------------------------------------------------------

/// v1 `ItemCrypto.open` / `openFile`, verbatim ('|'-delimited contexts,
/// header version byte 1).
abstract final class ItemCryptoV1 {
  static List<int> keyContext(String vaultId, Tier t, String itemId) =>
      utf8Bytes('ssb/v1/ik|vault:$vaultId|tier:${t.name}|item:$itemId');
  static List<int> bodyContext(String vaultId, String itemId) =>
      utf8Bytes('ssb/v1/item|vault:$vaultId|item:$itemId');

  static Future<Uint8List> open({
    required String vaultId,
    required Uint8List tierKey,
    required SealedItem item,
  }) async {
    final ik = await Aead.openLegacyV1(tierKey, item.wrappedItemKey,
        type: ObjectType.wrappedKey, context: keyContext(vaultId, item.tier, item.itemId));
    try {
      return _unpad(await Aead.openLegacyV1(ik, item.body,
          type: ObjectType.item, context: bodyContext(vaultId, item.itemId)));
    } finally {
      wipe(ik);
    }
  }

  static Future<Uint8List> openFile({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required String fileId,
    required Uint8List wrappedKey,
    required Uint8List stream,
  }) async {
    final fk = await Aead.openLegacyV1(tierKey, wrappedKey,
        type: ObjectType.wrappedKey, context: keyContext(vaultId, tier, fileId));
    try {
      return _unpad(await StreamCipher.decryptLegacyV1(fk, stream,
          context: bodyContext(vaultId, fileId)));
    } finally {
      wipe(fk);
    }
  }

  static Uint8List _unpad(Uint8List p) {
    if (p.length < 4) throw const SsbCryptoException('decrypt failed');
    final len = ByteData.sublistView(p).getUint32(0);
    if (len > p.length - 4) throw const SsbCryptoException('decrypt failed');
    if (!isAllZero(Uint8List.sublistView(p, 4 + len))) {
      throw const SsbCryptoException('decrypt failed');
    }
    return Uint8List.fromList(p.sublist(4, 4 + len));
  }
}

/// The v1 tier export the app sealed in its backend layer (ObjectType.item,
/// context `ssb/v1/tier-export|vault:<id>|tier:<t>`): a JSON bundle of
/// sealed items. No epoch, no sequence -- replayable by design, which is why
/// it is being replaced.
abstract final class TierExportV1 {
  static List<int> context(String vaultId, Tier tier) =>
      utf8Bytes('ssb/v1/tier-export|vault:$vaultId|tier:${tier.name}');

  static Future<Uint8List> open({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required Uint8List ciphertext,
  }) =>
      Aead.openLegacyV1(tierKey, ciphertext,
          type: ObjectType.item, context: context(vaultId, tier));
}
