import 'dart:typed_data';

import 'aead.dart';
import 'bytes.dart';
import 'kit_code.dart';
import 'stream.dart';
import 'suite.dart';

/// Release tiers (spec §5).
enum Tier { ice, essentials, secrets }

/// Key hierarchy (spec §6.2):
///
///   Unlock Key (passphrase+Secret Key) ─┐
///   Recovery Key (printed kit) ─────────┴─ wrap ─> Vault Key
///   Vault Key ─ wrap ─> Tier Key (one per tier, rotatable)
///   Tier Key  ─ wrap ─> Item Key (one per item / file)
///   Item Key  ─ AES-256-GCM ─> item body / file stream
///
/// Every wrap binds the vault id, tier and item id into the AAD, so a
/// wrapped key or ciphertext moved to another slot fails to open.
class VaultKeyring {
  final String vaultId;
  final Uint8List vaultKey;

  /// Raw key map. Prefer [tierKey], which refuses to hand out a wiped key.
  final Map<Tier, Uint8List> tierKeys;
  bool _disposed = false;
  VaultKeyring._(this.vaultId, this.vaultKey, this.tierKeys);

  /// True once [dispose] has run. Every key-using method throws after that,
  /// so a keyring that was locked mid-operation can never seal, wrap or
  /// split under the zeroed buffers it now holds.
  bool get isDisposed => _disposed;

  /// The live key for [t]. Throws [SsbCryptoException] once disposed.
  Uint8List tierKey(Tier t) {
    _checkLive();
    return tierKeys[t]!;
  }

  void _checkLive() {
    if (_disposed) throw const SsbCryptoException('keyring disposed');
  }

  static const recoveryKeyLabel = 'SSB1-RK';

  factory VaultKeyring.create(String vaultId) => VaultKeyring._(
      vaultId, randomBytes(32), {for (final t in Tier.values) t: randomBytes(32)});

  static Future<String> formatRecoveryKey(Uint8List rk) => KitCode.encode(recoveryKeyLabel, rk);
  static Future<Uint8List> parseRecoveryKey(String code) =>
      KitCode.decode(recoveryKeyLabel, code, payloadLength: 32);

  List<int> _ctx(String what) => utf8Bytes('ssb/v1/$what|vault:$vaultId');

  /// Vault Key wrapped under a 32-byte unlock or recovery key.
  ///
  /// Safe to race with [rotateTier] / [dispose]: [Aead.seal] snapshots its
  /// inputs before its first await, so a wipe that lands while this future
  /// is pending cannot change what gets sealed (report SSB-2026-001).
  Future<Uint8List> wrapVaultKey(Uint8List kek, {required String slot}) {
    _checkLive();
    return Aead.seal(kek, vaultKey, type: ObjectType.wrappedKey, context: _ctx('vk/$slot'));
  }

  /// See [wrapVaultKey] for the concurrency guarantee.
  Future<Uint8List> wrapTierKey(Tier t) {
    _checkLive();
    return Aead.seal(vaultKey, tierKeys[t]!,
        type: ObjectType.wrappedKey, context: _ctx('tk/${t.name}'));
  }

  /// Re-opens a keyring from its stored wrapped keys.
  ///
  /// Fails closed: if any wrapped key is rejected, every key already
  /// unwrapped (the Vault Key included) is wiped before the error leaves.
  static Future<VaultKeyring> open({
    required String vaultId,
    required Uint8List kek,
    required String slot,
    required Uint8List wrappedVaultKey,
    required Map<Tier, Uint8List> wrappedTierKeys,
  }) async {
    List<int> ctx(String w) => utf8Bytes('ssb/v1/$w|vault:$vaultId');
    final vk = await Aead.open(kek, wrappedVaultKey,
        type: ObjectType.wrappedKey, context: ctx('vk/$slot'));
    final tks = <Tier, Uint8List>{};
    try {
      for (final e in wrappedTierKeys.entries) {
        tks[e.key] = await Aead.open(vk, e.value,
            type: ObjectType.wrappedKey, context: ctx('tk/${e.key.name}'));
      }
    } catch (_) {
      wipe(vk);
      tks.values.forEach(wipe);
      rethrow;
    }
    return VaultKeyring._(vaultId, vk, tks);
  }

  /// Re-opens a keyring straight from the Vault Key, skipping the passphrase.
  ///
  /// For biometric unlock, where the device keystore hands back the Vault Key
  /// after the OS has checked a face or fingerprint. The passphrase path is
  /// still the only way to DERIVE this key; this only re-opens it.
  ///
  /// [vaultKey] is copied: the keyring owns its own buffer, so [dispose]
  /// never zeroes a buffer the caller still holds and the caller's wipe
  /// never zeroes the keyring. The caller should wipe its copy once done.
  static Future<VaultKeyring> fromVaultKey({
    required String vaultId,
    required Uint8List vaultKey,
    required Map<Tier, Uint8List> wrappedTierKeys,
  }) async {
    final vk = Uint8List.fromList(vaultKey);
    final tks = <Tier, Uint8List>{};
    try {
      for (final e in wrappedTierKeys.entries) {
        tks[e.key] = await Aead.open(vk, e.value,
            type: ObjectType.wrappedKey,
            context: utf8Bytes('ssb/v1/tk/${e.key.name}|vault:$vaultId'));
      }
    } catch (_) {
      wipe(vk);
      tks.values.forEach(wipe);
      rethrow;
    }
    return VaultKeyring._(vaultId, vk, tks);
  }

  /// Rotate one tier (e.g. after removing a beneficiary). Items in that tier
  /// must be re-wrapped with [ItemCrypto.rewrapItemKey].
  ///
  /// The old key buffer is wiped in place. A [wrapTierKey] call that is
  /// still pending for this tier keeps sealing the OLD key (it took its own
  /// snapshot), which is the value the caller asked for at the time.
  void rotateTier(Tier t) {
    _checkLive();
    wipe(tierKeys[t]);
    tierKeys[t] = randomBytes(32);
  }

  /// Wipes every key in place and marks the keyring dead. Pending seals that
  /// were started before this call still complete with the values they were
  /// given; nothing started after it can use this keyring ([isDisposed]).
  void dispose() {
    _disposed = true;
    wipe(vaultKey);
    tierKeys.values.forEach(wipe);
  }
}

/// A sealed vault item as stored on the server: nothing here is readable
/// without the tier key.
class SealedItem {
  final String itemId;
  final Tier tier;
  final Uint8List wrappedItemKey;
  final Uint8List body;
  SealedItem(this.itemId, this.tier, this.wrappedItemKey, this.body);
}

abstract final class ItemCrypto {
  // The '|'-delimited contexts below are safe: the key-wrap and body AADs are used under different keys, so (key, AAD) is injective even if an id contained '|'. New code should length-prefix instead (see ssb/v2/*).
  static List<int> _keyCtx(String vaultId, Tier t, String itemId) =>
      utf8Bytes('ssb/v1/ik|vault:$vaultId|tier:${t.name}|item:$itemId');
  static List<int> _bodyCtx(String vaultId, String itemId) =>
      utf8Bytes('ssb/v1/item|vault:$vaultId|item:$itemId');

  /// Encrypts an item (title, fields, notes all go inside [plaintext], so no
  /// metadata leaks) under a fresh item key.
  static Future<SealedItem> seal({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required String itemId,
    required Uint8List plaintext,
  }) async {
    // Pad (= copy) the plaintext before the first await, so the caller's
    // buffer is never read after this function has yielded (see Aead.seal).
    final padded = _pad(plaintext);
    final ik = randomBytes(32);
    try {
      return SealedItem(
        itemId,
        tier,
        await Aead.seal(tierKey, ik, type: ObjectType.wrappedKey, context: _keyCtx(vaultId, tier, itemId)),
        await Aead.seal(ik, padded, type: ObjectType.item, context: _bodyCtx(vaultId, itemId)),
      );
    } finally {
      wipe(ik);
      wipe(padded);
    }
  }

  static Future<Uint8List> open({
    required String vaultId,
    required Uint8List tierKey,
    required SealedItem item,
  }) async {
    final ik = await Aead.open(tierKey, item.wrappedItemKey,
        type: ObjectType.wrappedKey, context: _keyCtx(vaultId, item.tier, item.itemId));
    try {
      return _unpad(await Aead.open(ik, item.body,
          type: ObjectType.item, context: _bodyCtx(vaultId, item.itemId)));
    } finally {
      wipe(ik);
    }
  }

  /// Moves an item key to a new tier key (tier rotation or re-tiering)
  /// without touching the (possibly large) body.
  static Future<SealedItem> rewrapItemKey({
    required String vaultId,
    required SealedItem item,
    required Uint8List oldTierKey,
    required Tier newTier,
    required Uint8List newTierKey,
  }) async {
    // newTierKey is only used AFTER the first await (the unwrap), so it is
    // snapshotted here; a rotation or dispose() landing in between must
    // not re-wrap the item key under zeros (audit finding F1, 2026-10-15).
    final nk = Uint8List.fromList(newTierKey);
    try {
      final ik = await Aead.open(oldTierKey, item.wrappedItemKey,
          type: ObjectType.wrappedKey, context: _keyCtx(vaultId, item.tier, item.itemId));
      try {
        // The body is copied so the new item never aliases the old one:
        // wiping or dropping the old SealedItem must not touch the new one.
        return SealedItem(item.itemId, newTier,
            await Aead.seal(nk, ik, type: ObjectType.wrappedKey, context: _keyCtx(vaultId, newTier, item.itemId)),
            Uint8List.fromList(item.body));
      } finally {
        wipe(ik);
      }
    } finally {
      wipe(nk);
    }
  }

  /// Files: a per-file key wrapped under the tier key, body via STREAM.
  static Future<(Uint8List wrappedKey, Uint8List stream)> sealFile({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required String fileId,
    required Uint8List data,
  }) async {
    // Pad (= copy) before the first await; the padded buffer is private to
    // this call, which is what StreamCipher.encrypt relies on.
    final padded = _pad(data);
    final fk = randomBytes(32);
    try {
      return (
        await Aead.seal(tierKey, fk, type: ObjectType.wrappedKey, context: _keyCtx(vaultId, tier, fileId)),
        await StreamCipher.encrypt(fk, padded, context: _bodyCtx(vaultId, fileId)),
      );
    } finally {
      wipe(fk);
      wipe(padded);
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
    final fk = await Aead.open(tierKey, wrappedKey,
        type: ObjectType.wrappedKey, context: _keyCtx(vaultId, tier, fileId));
    try {
      return _unpad(await StreamCipher.decrypt(fk, stream, context: _bodyCtx(vaultId, fileId)));
    } finally {
      wipe(fk);
    }
  }

  /// Padmé-style padding (Nikitin et al.) to hide exact sizes: pads to a
  /// bucket that leaks at most O(log log n) bits. Format: len(4) | data | 0s.
  static Uint8List _pad(Uint8List data) {
    final n = data.length + 4;
    final target = padmeLength(n < 256 ? 256 : n);
    return Uint8List(target)
      ..setAll(0, u32be(data.length))
      ..setAll(4, data);
  }

  static Uint8List _unpad(Uint8List p) {
    if (p.length < 4) throw const SsbCryptoException('decrypt failed');
    final len = ByteData.sublistView(p).getUint32(0);
    if (len > p.length - 4) throw const SsbCryptoException('decrypt failed');
    return Uint8List.fromList(p.sublist(4, 4 + len));
  }

  static int padmeLength(int l) {
    if (l < 2) return l;
    final e = l.bitLength - 1; // floor(log2 l)
    final s = e.bitLength; // floor(log2 e) + 1
    final z = e - s;
    final mask = (1 << z) - 1;
    return (l + mask) & ~mask;
  }
}
