import 'dart:async';
import 'dart:typed_data';

import 'aead.dart';
import 'bytes.dart';
import 'freshness.dart';
import 'kit_code.dart';
import 'manifest.dart';
import 'owner_identity.dart';
import 'shamir.dart';
import 'stream.dart';
import 'suite.dart';

/// Release tiers (spec §5).
enum Tier { ice, essentials, secrets }

/// Key hierarchy (spec §6.2), format v2 (SSB-2026-002):
///
///   Unlock Key (passphrase+Secret Key) ─┐
///   Recovery Key (printed kit) ─────────┴─ wrap ─> Vault Key      ctx vk(vaultId, slot, slotEpoch)
///   Vault Key ─ wrap ─> Tier Key (one per tier, rotatable)        ctx tk(vaultId, tier, tierEpoch)
///   Vault Key ─ seal ─> Manifest (seq, epochs, hashes)            ctx manifest(vaultId)
///   Tier Key  ─ wrap ─> Item Key (one per item / file)            ctx ik(vaultId, tier, tierEpoch, itemId)
///   Item Key  ─ AES-256-GCM ─> item body / file stream            ctx item/file(vaultId, id)
///   Tier Key  ─ seal ─> tier export for the server                ctx tier-export(vaultId, tier, epoch, seq, prevHash)
///
/// Every wrap binds the vault id, the slot/tier/item id AND the key
/// generation (epoch) into the AAD, all length-prefixed (`ctx2`). The sealed
/// [VaultManifest] says which generation is current and which stored
/// objects belong to it, and a per-device [FreshnessAnchor] refuses older
/// manifests. So a wrapped key, a slot, an item or a manifest that a server
/// replays from before a rotation / passphrase change / edit fails to open
/// instead of quietly rolling the vault back (findings F2a, F2b, F3, F4).
///
/// Format-v1 keyrings are opened only through `VaultKeyringV1` in
/// `package:ssb_crypto/legacy_v1.dart` (the migration), never here.
class VaultKeyring {
  final String vaultId;
  final Uint8List vaultKey;

  /// Raw key map. Prefer [tierKey], which refuses to hand out a wiped key.
  final Map<Tier, Uint8List> tierKeys;

  /// Current key generation of each tier. Bumped by [rotateTier].
  final Map<Tier, int> tierEpochs;

  /// Current generation of each Vault-Key slot wrap (`unlock`, `recovery`).
  /// Set by [wrapVaultKey]; 0 marks a slot still wrapped in format v1
  /// (see [recordLegacySlot]).
  final Map<String, int> slotEpochs;

  /// The anchor this keyring commits its manifest sequence to.
  final FreshnessAnchor anchor;

  /// True when [open] / [fromVaultKey] found no anchor for this vault on
  /// this device and accepted the manifest on faith (new device, cleared
  /// storage). The app should say so and offer a rotation (design D7).
  final bool restoredWithoutAnchor;

  final Map<String, String> _slotHashes;
  final Map<Tier, int> _tierExportSeq;
  final Map<Tier, String> _tierExportHead;
  final Map<Tier, Future<void>> _exportTail = {};
  String _itemsHash;
  String _beneficiarySetHash;
  int _seq;
  bool _disposed = false;

  VaultKeyring._({
    required this.vaultId,
    required this.vaultKey,
    required this.tierKeys,
    required this.tierEpochs,
    required this.slotEpochs,
    required this.anchor,
    required Map<String, String> slotHashes,
    required Map<Tier, int> tierExportSeq,
    required Map<Tier, String> tierExportHead,
    required String itemsHash,
    required String beneficiarySetHash,
    required int seq,
    this.restoredWithoutAnchor = false,
  })  : _slotHashes = slotHashes,
        _tierExportSeq = tierExportSeq,
        _tierExportHead = tierExportHead,
        _itemsHash = itemsHash,
        _beneficiarySetHash = beneficiarySetHash,
        _seq = seq;

  /// True once [dispose] has run. Every key-using method throws after that,
  /// so a keyring that was locked mid-operation can never seal, wrap or
  /// split under the zeroed buffers it now holds.
  bool get isDisposed => _disposed;

  /// The live key for [t]. Throws [SsbCryptoException] once disposed, or if
  /// this keyring holds no key for [t].
  Uint8List tierKey(Tier t) {
    _checkLive();
    return _tier(t);
  }

  /// The current generation of [t] (what [wrapTierKey], `ItemCrypto` and
  /// `Release.create` must be given for this tier).
  int tierEpoch(Tier t) {
    final e = tierEpochs[t];
    if (e == null) throw const SsbCryptoException('missing tier key');
    return e;
  }

  /// The generation the NEXT [wrapVaultKey] of [slot] should use.
  int nextSlotEpoch(String slot) => (slotEpochs[slot] ?? 0) + 1;

  /// Manifest sequence number of the last [sealManifest] (0 for a fresh keyring).
  int get seq => _seq;

  /// Latest tier-export sequence for [t], 0 if never exported.
  int tierExportSeq(Tier t) => _tierExportSeq[t] ?? 0;

  /// Hex SHA-256 of the latest tier export for [t], or null if never exported.
  String? tierExportHead(Tier t) => _tierExportHead[t];

  /// The manifest as it stands now (what the next [sealManifest] will seal,
  /// minus the seq bump).
  VaultManifest get manifest => VaultManifest(
        vaultId: vaultId,
        seq: _seq,
        tierEpochs: Map.of(tierEpochs),
        slotEpochs: Map.of(slotEpochs),
        slotHashes: Map.of(_slotHashes),
        tierExportSeq: Map.of(_tierExportSeq),
        tierExportHead: Map.of(_tierExportHead),
        itemsHash: _itemsHash,
        beneficiarySetHash: _beneficiarySetHash,
      );

  void _checkLive() {
    if (_disposed) throw const SsbCryptoException('keyring disposed');
  }

  /// The raw key for [t], as the package's one typed error rather than a
  /// null-check TypeError when it is missing (red team 2026-10-20, B2).
  Uint8List _tier(Tier t) {
    final k = tierKeys[t];
    if (k == null) throw const SsbCryptoException('missing tier key');
    return k;
  }

  /// Every tier must be present before a keyring is built. One opened from
  /// a partial map would look healthy, fail with a TypeError on first use
  /// of the missing tier and -- worse -- let [rotateTier] mint a fresh key
  /// for it, orphaning every item sealed under the real (withheld) one. So a
  /// server or file that is missing a tier fails closed here (B2).
  static void _requireAllTiers(Map<Tier, Uint8List> wrapped) {
    for (final t in Tier.values) {
      if (!wrapped.containsKey(t)) {
        throw const SsbCryptoException('missing tier key');
      }
    }
  }

  static const recoveryKeyLabel = 'SSB1-RK';

  /// Largest tier epoch a kit can carry (the share's u16 field).
  static const maxTierEpoch = Share.maxEpoch;

  /// First generation of every tier in a new or migrated vault.
  static const firstEpoch = 1;

  /// A brand-new vault: fresh Vault Key, fresh tier keys at [firstEpoch],
  /// manifest sequence 0, no slots wrapped yet.
  ///
  /// [anchor] is where the manifest sequence is committed; the app passes
  /// its `DeviceAnchor`. The default [InMemoryAnchor] is for tests and
  /// one-shot tools -- a vault created with it has no freshness protection
  /// until it is next opened with a real anchor.
  ///
  /// DEPRECATED for the app: the id is chosen by the caller, so nothing binds
  /// it to the Vault Key. New vaults use [createSelfCertifying]; this stays
  /// for tests and fixtures that need a fixed id, and for format-v1 vaults.
  factory VaultKeyring.create(String vaultId, {FreshnessAnchor? anchor}) =>
      VaultKeyring._fresh(vaultId, randomBytes(32), anchor ?? InMemoryAnchor());

  /// A brand-new vault whose id is DERIVED from its Vault Key
  /// ([OwnerIdentity.vaultIdFor] of the key's Ed25519 owner identity, CRYPTO-DESIGN
  /// §6.2): the Vault Key is generated first, then the id, then the keyring.
  /// The server can therefore verify that whoever registers this id holds the
  /// key, which is what closes vault-id squatting. The id is
  /// `OwnerIdentity.derive(keyring.vaultKey).vaultId`, always.
  static Future<VaultKeyring> createSelfCertifying({FreshnessAnchor? anchor}) async {
    final vk = randomBytes(32);
    try {
      final id = await OwnerIdentity.derive(vk);
      return VaultKeyring._fresh(id.vaultId, vk, anchor ?? InMemoryAnchor());
    } catch (_) {
      wipe(vk);
      rethrow;
    }
  }

  /// A v2 keyring around an EXISTING Vault Key, for the v1 -> v2 migration
  /// (design D12): the Vault Key is kept (so the printed Recovery Key still
  /// works), every tier gets a fresh key at [firstEpoch], and the caller
  /// re-seals every item under it. [vaultKey] is copied.
  factory VaultKeyring.adopt({
    required String vaultId,
    required Uint8List vaultKey,
    required FreshnessAnchor anchor,
  }) {
    _checkVaultKey(vaultKey);
    return VaultKeyring._fresh(vaultId, Uint8List.fromList(vaultKey), anchor);
  }

  factory VaultKeyring._fresh(String vaultId, Uint8List vk, FreshnessAnchor anchor) =>
      VaultKeyring._(
        vaultId: vaultId,
        vaultKey: vk,
        tierKeys: {for (final t in Tier.values) t: randomBytes(32)},
        tierEpochs: {for (final t in Tier.values) t: firstEpoch},
        slotEpochs: {},
        anchor: anchor,
        slotHashes: {},
        tierExportSeq: {},
        tierExportHead: {},
        itemsHash: VaultManifest.itemsHashHex(const []),
        beneficiarySetHash: VaultManifest.beneficiarySetHashHex(const []),
        seq: 0,
      );

  static void _checkVaultKey(Uint8List vaultKey) {
    if (vaultKey.length != Aead.keyLength || isAllZero(vaultKey)) {
      throw const SsbCryptoException('bad vault key');
    }
  }

  static Future<String> formatRecoveryKey(Uint8List rk) => KitCode.encode(recoveryKeyLabel, rk);
  static Future<Uint8List> parseRecoveryKey(String code) =>
      KitCode.decode(recoveryKeyLabel, code, payloadLength: 32);

  // ---- contexts ----------------------------------------------------------

  /// AAD for a Vault-Key slot wrap at [epoch].
  static List<int> vkContext(String vaultId, String slot, int epoch) =>
      ctx2('vk', [vaultId, slot, u32be(epoch)]);

  /// AAD for a tier-key wrap at [epoch].
  static List<int> tkContext(String vaultId, Tier t, int epoch) =>
      ctx2('tk', [vaultId, t.name, u32be(epoch)]);

  /// The format-v1 slot context, used ONLY to open a slot whose cleartext
  /// epoch is 0 (a recovery slot the migration left in v1 until the owner
  /// next types the Recovery Key, design D12). `VaultKeyringV1` reuses it.
  static List<int> legacyVkContext(String vaultId, String slot) =>
      utf8Bytes('ssb/v1/vk/$slot|vault:$vaultId');

  static void _checkEpoch(int epoch) {
    if (epoch < 0 || epoch > VaultManifest.maxU32) {
      throw const SsbCryptoException('bad epoch');
    }
  }

  // ---- wrapping ----------------------------------------------------------

  /// Vault Key wrapped under a 32-byte unlock or recovery key for [slot] at
  /// generation [epoch] (>= 1; use [nextSlotEpoch] when re-wrapping after a
  /// passphrase change). Records the slot's epoch and the blob's hash so the
  /// next [sealManifest] binds them; the caller stores the blob.
  ///
  /// Safe to race with [rotateTier] / [dispose]: [Aead.seal] snapshots its
  /// inputs before its first await, so a wipe that lands while this future
  /// is pending cannot change what gets sealed (report SSB-2026-001).
  Future<Uint8List> wrapVaultKey(Uint8List kek, {required String slot, required int epoch}) async {
    _checkLive();
    _checkEpoch(epoch);
    if (epoch == 0) throw const SsbCryptoException('bad epoch'); // 0 is reserved for v1 wraps
    final blob = await Aead.seal(kek, vaultKey,
        type: ObjectType.wrappedKey, context: vkContext(vaultId, slot, epoch));
    slotEpochs[slot] = epoch;
    _slotHashes[slot] = hexEncode(sha256Of(blob));
    return blob;
  }

  /// Migration only (design D12): registers a slot that is still a FORMAT-V1
  /// wrap of this Vault Key, as epoch 0 with its hash, so the manifest binds
  /// it and [open] can accept it through the legacy context once, after
  /// which the app re-wraps it with [wrapVaultKey].
  void recordLegacySlot(String slot, Uint8List wrappedVaultKeyV1) {
    _checkLive();
    slotEpochs[slot] = 0;
    _slotHashes[slot] = hexEncode(sha256Of(wrappedVaultKeyV1));
  }

  /// Tier key for [t] wrapped under the Vault Key at the tier's current
  /// epoch. See [wrapVaultKey] for the concurrency guarantee.
  Future<Uint8List> wrapTierKey(Tier t) {
    _checkLive();
    return Aead.seal(vaultKey, _tier(t),
        type: ObjectType.wrappedKey, context: tkContext(vaultId, t, tierEpoch(t)));
  }

  // ---- opening -----------------------------------------------------------

  /// Re-opens a keyring from its stored objects, checking every one of them
  /// against the sealed manifest, in this order (design D6):
  ///
  ///  1. Vault Key from [wrappedVaultKey] under [slot] at the CLEARTEXT
  ///     [slotEpochs]`[slot]` (an epoch-0 slot is a v1 wrap, see
  ///     [recordLegacySlot]);
  ///  2. the manifest, which must be for [vaultId];
  ///  3. the manifest's slot epoch and slot hash must match what was just
  ///     used (a replayed older slot wrap fails here, F3), and its `seq`
  ///     must be >= the device [anchor] (an older manifest fails here, F4);
  ///  4. every tier key under its manifest epoch;
  ///  5. [items] must hash to the manifest's `itemsHash` (F2a/F2b).
  ///
  /// Only then is the anchor advanced (if `seq` moved) and the keyring
  /// returned. Fails closed: on any error every key already unwrapped (the
  /// Vault Key included) is wiped before the error leaves. All tiers must be
  /// present (B2).
  static Future<VaultKeyring> open({
    required String vaultId,
    required Uint8List kek,
    required String slot,
    required Uint8List wrappedVaultKey,
    required Map<String, int> slotEpochs,
    required Uint8List manifestBlob,
    required Map<Tier, Uint8List> wrappedTierKeys,
    required List<SealedItem> items,
    required FreshnessAnchor anchor,
  }) async {
    _requireAllTiers(wrappedTierKeys);
    final slotEpoch = slotEpochs[slot];
    if (slotEpoch == null || slotEpoch < 0 || slotEpoch > VaultManifest.maxU32) {
      throw const SsbCryptoException('stale slot');
    }
    final vk = slotEpoch == 0
        ? await Aead.openLegacyV1(kek, wrappedVaultKey,
            type: ObjectType.wrappedKey, context: legacyVkContext(vaultId, slot))
        : await Aead.open(kek, wrappedVaultKey,
            type: ObjectType.wrappedKey, context: vkContext(vaultId, slot, slotEpoch));
    try {
      final m = await VaultManifest.open(vk, manifestBlob, vaultId: vaultId);
      if (m.slotEpochs[slot] != slotEpoch ||
          m.slotHashes[slot] != hexEncode(sha256Of(wrappedVaultKey))) {
        throw const SsbCryptoException('stale slot');
      }
      return await _finishOpen(vaultId, vk, m, wrappedTierKeys, items, anchor);
    } catch (_) {
      wipe(vk);
      rethrow;
    }
  }

  /// Re-opens a keyring straight from the Vault Key, skipping the passphrase.
  ///
  /// For biometric unlock, where the device keystore hands back the Vault Key
  /// after the OS has checked a face or fingerprint. The passphrase path is
  /// still the only way to DERIVE this key; this only re-opens it.
  ///
  /// Same checks as [open] minus the slot (steps 2, 3-seq, 4, 5).
  ///
  /// [vaultKey] is copied: the keyring owns its own buffer, so [dispose]
  /// never zeroes a buffer the caller still holds and the caller's wipe
  /// never zeroes the keyring. The caller should wipe its copy once done.
  /// Fails closed like [open]: the Vault Key must be 32 non-zero bytes (a
  /// zero key is a wiped keystore buffer) and every tier must be present.
  static Future<VaultKeyring> fromVaultKey({
    required String vaultId,
    required Uint8List vaultKey,
    required Uint8List manifestBlob,
    required Map<Tier, Uint8List> wrappedTierKeys,
    required List<SealedItem> items,
    required FreshnessAnchor anchor,
  }) async {
    _checkVaultKey(vaultKey);
    _requireAllTiers(wrappedTierKeys);
    final vk = Uint8List.fromList(vaultKey);
    try {
      final m = await VaultManifest.open(vk, manifestBlob, vaultId: vaultId);
      return await _finishOpen(vaultId, vk, m, wrappedTierKeys, items, anchor);
    } catch (_) {
      wipe(vk);
      rethrow;
    }
  }

  /// Steps 3 (seq), 4 and 5 of [open]; takes ownership of [vk] on success
  /// only (the caller wipes it on failure).
  static Future<VaultKeyring> _finishOpen(
    String vaultId,
    Uint8List vk,
    VaultManifest m,
    Map<Tier, Uint8List> wrappedTierKeys,
    List<SealedItem> items,
    FreshnessAnchor anchor,
  ) async {
    final last = await anchor.lastSeq(vaultId);
    if (last != null && m.seq < last) {
      throw const SsbCryptoException('stale manifest');
    }
    final tks = <Tier, Uint8List>{};
    try {
      for (final t in Tier.values) {
        tks[t] = await Aead.open(vk, wrappedTierKeys[t]!,
            type: ObjectType.wrappedKey,
            context: tkContext(vaultId, t, m.tierEpochs[t]!));
      }
      if (m.itemsHash != VaultManifest.itemsHashHex(items)) {
        throw const SsbCryptoException('items do not match manifest');
      }
    } catch (_) {
      tks.values.forEach(wipe);
      rethrow;
    }
    // Everything checked out: this is now the oldest state this device will
    // accept. (A missing anchor is accepted and reported, design D7.)
    if (last == null || m.seq > last) await anchor.commit(vaultId, m.seq);
    return VaultKeyring._(
      vaultId: vaultId,
      vaultKey: vk,
      tierKeys: tks,
      tierEpochs: Map.of(m.tierEpochs),
      slotEpochs: Map.of(m.slotEpochs),
      anchor: anchor,
      slotHashes: Map.of(m.slotHashes),
      tierExportSeq: Map.of(m.tierExportSeq),
      tierExportHead: Map.of(m.tierExportHead),
      itemsHash: m.itemsHash,
      beneficiarySetHash: m.beneficiarySetHash,
      seq: m.seq,
      restoredWithoutAnchor: last == null,
    );
  }

  // ---- manifest ----------------------------------------------------------

  /// Seals the manifest for the state about to be written: `seq + 1`, the
  /// current epochs and slot hashes, the hash of [items] (the complete item
  /// set the file will hold) and, if given, of [beneficiaryEntries].
  ///
  /// Call it on EVERY write, store the blob beside the items, and after the
  /// write has succeeded call [commitManifest]. The sequence is bumped
  /// before the first await, so two overlapping calls never seal the same
  /// number; a write that then fails simply leaves a gap.
  Future<Uint8List> sealManifest({
    required List<SealedItem> items,
    Iterable<String>? beneficiaryEntries,
  }) {
    _checkLive();
    if (_seq >= VaultManifest.maxU32) throw const SsbCryptoException('manifest sequence exhausted');
    _seq += 1;
    _itemsHash = VaultManifest.itemsHashHex(items);
    if (beneficiaryEntries != null) {
      _beneficiarySetHash = VaultManifest.beneficiarySetHashHex(beneficiaryEntries);
    }
    return VaultManifest.seal(vaultKey, manifest);
  }

  /// Records the current manifest sequence in the device [anchor]. Call it
  /// AFTER the file holding that manifest has been written (design D7).
  Future<void> commitManifest() => anchor.commit(vaultId, _seq);

  // ---- tier exports ------------------------------------------------------

  /// Seals the next export of tier [t] for the server: `seq` = previous + 1,
  /// `prevHash` = hash of the previous export (zeros for the first), under
  /// the tier's current key and epoch. Updates the chain head so the next
  /// [sealManifest] binds it.
  ///
  /// Safe to call without awaiting the previous call for the same tier (the
  /// app pushes a tier from an unawaited task after every write): the key,
  /// epoch and plaintext are snapshotted before the first await, like every
  /// other seal here, and calls for one tier run strictly one after another,
  /// so each export gets its own `seq` and chains to the previous one's hash.
  /// Before this (red team 2026-10-26) two overlapping calls both read
  /// `seq = n + 1` and the same `prevHash`, producing a forked chain whose
  /// recorded head could point at an export the server never accepted.
  Future<TierExport> sealTierExport(Tier t, Uint8List plaintext) async {
    _checkLive();
    final key = Uint8List.fromList(_tier(t));
    final epoch = tierEpoch(t);
    final pt = Uint8List.fromList(plaintext);
    final previous = _exportTail[t];
    final turn = Completer<void>();
    _exportTail[t] = turn.future;
    try {
      if (previous != null) await previous;
      final seq = tierExportSeq(t) + 1;
      if (seq > VaultManifest.maxU32) throw const SsbCryptoException('export sequence exhausted');
      final head = _tierExportHead[t];
      final prevHash = head == null ? TierExportCrypto.genesisPrevHash : hexDecode(head);
      final export = await TierExportCrypto.seal(
        vaultId: vaultId, tier: t, tierKey: key, epoch: epoch,
        seq: seq, prevHash: prevHash, plaintext: pt,
      );
      _tierExportSeq[t] = seq;
      _tierExportHead[t] = hexEncode(TierExportCrypto.hash(export.ciphertext));
      return export;
    } finally {
      wipe(key);
      wipe(pt);
      turn.complete();
    }
  }

  // ---- rotation / disposal -----------------------------------------------

  /// Rotate one tier (e.g. after removing a beneficiary): fresh key, epoch
  /// + 1. Items in that tier must be re-wrapped with
  /// [ItemCrypto.rewrapItemKey] (old epoch -> new epoch), every beneficiary
  /// needs a new Kit, and the manifest must be re-sealed.
  ///
  /// The old key buffer is wiped in place. A [wrapTierKey] call that is
  /// still pending for this tier keeps sealing the OLD key under the OLD
  /// epoch (it took its own snapshot), which is the value the caller asked
  /// for at the time.
  void rotateTier(Tier t) {
    _checkLive();
    // _tier throws for a missing tier: rotation must never MINT a key for a
    // tier this keyring never held (B2).
    final old = _tier(t);
    final e = tierEpoch(t);
    if (e >= maxTierEpoch) throw const SsbCryptoException('bad epoch');
    wipe(old);
    tierKeys[t] = randomBytes(32);
    tierEpochs[t] = e + 1;
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
  /// Item-key wrap context: vault, tier, TIER EPOCH, item id (design D8). An
  /// item wrapped before a rotation cannot be opened under the rotated
  /// keyring even if the same key bytes were somehow reused (F2b).
  static List<int> keyContext(String vaultId, Tier t, int tierEpoch, String itemId) =>
      ctx2('ik', [vaultId, t.name, u32be(tierEpoch), itemId]);

  /// Item body context (under the per-item key).
  static List<int> bodyContext(String vaultId, String itemId) =>
      ctx2('item', [vaultId, itemId]);

  /// File stream context (under the per-file key).
  static List<int> fileContext(String vaultId, String fileId) =>
      ctx2('file', [vaultId, fileId]);

  /// Encrypts an item (title, fields, notes all go inside [plaintext], so no
  /// metadata leaks) under a fresh item key, wrapped under [tierKey] at
  /// [tierEpoch] (`keyring.tierEpoch(tier)`).
  static Future<SealedItem> seal({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required int tierEpoch,
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
        await Aead.seal(tierKey, ik, type: ObjectType.wrappedKey,
            context: keyContext(vaultId, tier, tierEpoch, itemId)),
        await Aead.seal(ik, padded, type: ObjectType.item, context: bodyContext(vaultId, itemId)),
      );
    } finally {
      wipe(ik);
      wipe(padded);
    }
  }

  static Future<Uint8List> open({
    required String vaultId,
    required Uint8List tierKey,
    required int tierEpoch,
    required SealedItem item,
  }) async {
    // item.body is read after the first await below, so it is snapshotted
    // here: a caller that wipes or replaces the old item's buffer while this
    // open is pending must not change what gets opened (SSB-2026-001
    // follow-up, 2026-10-20).
    final body = Uint8List.fromList(item.body);
    final ik = await Aead.open(tierKey, item.wrappedItemKey,
        type: ObjectType.wrappedKey, context: keyContext(vaultId, item.tier, tierEpoch, item.itemId));
    try {
      return _unpad(await Aead.open(ik, body,
          type: ObjectType.item, context: bodyContext(vaultId, item.itemId)));
    } finally {
      wipe(ik);
    }
  }

  /// Moves an item key to a new tier key / epoch (tier rotation or
  /// re-tiering) without touching the (possibly large) body.
  static Future<SealedItem> rewrapItemKey({
    required String vaultId,
    required SealedItem item,
    required Uint8List oldTierKey,
    required int oldTierEpoch,
    required Tier newTier,
    required Uint8List newTierKey,
    required int newTierEpoch,
  }) async {
    // item.body is read after the awaits below as well (it goes into the
    // returned item), so it is snapshotted here too: a delete that wipes the
    // old item's body while a rotation re-wrap is pending must not turn into
    // a successful re-wrap of wiped bytes (SSB-2026-001 follow-up,
    // 2026-10-20). The copy is private to this call, so the new item also
    // never aliases the old one.
    final body = Uint8List.fromList(item.body);
    // newTierKey is only used AFTER the first await (the unwrap), so it is
    // snapshotted here; a rotation or dispose() landing in between must
    // not re-wrap the item key under zeros (audit finding F1, 2026-10-15).
    final nk = Uint8List.fromList(newTierKey);
    try {
      final ik = await Aead.open(oldTierKey, item.wrappedItemKey,
          type: ObjectType.wrappedKey,
          context: keyContext(vaultId, item.tier, oldTierEpoch, item.itemId));
      try {
        return SealedItem(item.itemId, newTier,
            await Aead.seal(nk, ik, type: ObjectType.wrappedKey,
                context: keyContext(vaultId, newTier, newTierEpoch, item.itemId)),
            body);
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
    required int tierEpoch,
    required String fileId,
    required Uint8List data,
  }) async {
    // Pad (= copy) before the first await; the padded buffer is private to
    // this call, which is what StreamCipher.encrypt relies on.
    final padded = _pad(data);
    final fk = randomBytes(32);
    try {
      return (
        await Aead.seal(tierKey, fk, type: ObjectType.wrappedKey,
            context: keyContext(vaultId, tier, tierEpoch, fileId)),
        await StreamCipher.encrypt(fk, padded, context: fileContext(vaultId, fileId)),
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
    required int tierEpoch,
    required String fileId,
    required Uint8List wrappedKey,
    required Uint8List stream,
  }) async {
    final fk = await Aead.open(tierKey, wrappedKey,
        type: ObjectType.wrappedKey, context: keyContext(vaultId, tier, tierEpoch, fileId));
    try {
      return _unpad(await StreamCipher.decrypt(fk, stream, context: fileContext(vaultId, fileId)));
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
    // Canonical padding only: [_pad] always fills with zeros, so anything
    // else after the data is a non-canonical encoding (a covert channel or a
    // corrupted encryptor), never a legitimate item. Compatible with every
    // item sealed so far (red team 2026-10-20, finding 3a).
    if (!isAllZero(Uint8List.sublistView(p, 4 + len))) {
      throw const SsbCryptoException('decrypt failed');
    }
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

/// Cleartext header stored beside a tier-export ciphertext in `tiers/{t}`
/// (design D9): `{v: 2, epoch, seq, prevHash}`. Every field is also inside
/// the ciphertext's AAD, so a server that edits the header breaks the open.
class TierExportHeader {
  static const version = 2;
  final int epoch;
  final int seq;

  /// SHA-256 of the previous export's ciphertext (32 zero bytes for the first).
  final Uint8List prevHash;

  TierExportHeader({required this.epoch, required this.seq, required Uint8List prevHash})
      : prevHash = Uint8List.fromList(prevHash) {
    if (epoch < 0 || epoch > VaultManifest.maxU32 || seq < 0 || seq > VaultManifest.maxU32 ||
        this.prevHash.length != 32) {
      throw const SsbCryptoException('bad tier export header');
    }
  }

  Map<String, Object> toJson() =>
      {'v': version, 'epoch': epoch, 'seq': seq, 'prevHash': hexEncode(prevHash)};

  /// Strict: `v` must be 2, ints in u32 range, `prevHash` 64 hex chars.
  factory TierExportHeader.fromJson(Map<String, dynamic> j) {
    final v = j['v'], epoch = j['epoch'], seq = j['seq'], ph = j['prevHash'];
    if (v != version || epoch is! int || seq is! int || ph is! String || ph.length != 64) {
      throw const SsbCryptoException('bad tier export header');
    }
    final Uint8List prev;
    try {
      prev = hexDecode(ph);
    } on FormatException {
      throw const SsbCryptoException('bad tier export header');
    }
    return TierExportHeader(epoch: epoch, seq: seq, prevHash: prev);
  }
}

/// One sealed tier export: the cleartext [header] and the [ciphertext].
class TierExport {
  final TierExportHeader header;
  final Uint8List ciphertext;
  TierExport(this.header, this.ciphertext);
}

/// Seals the per-tier bundle the server holds for beneficiaries
/// ([ObjectType.tierExport]) with AAD
/// `ctx2('tier-export', [vaultId, tier, u32(epoch), u32(seq), prevHash])`.
///
/// A beneficiary's recovery tool opens it with the tier key recovered from
/// the Kit; because the AAD carries the epoch and the chain position, an
/// export from an older generation or an older sequence fails to open
/// instead of being served as current (design D9/D11).
abstract final class TierExportCrypto {
  /// `prevHash` of the first export in a tier's chain.
  static final Uint8List genesisPrevHash = Uint8List(32);

  static List<int> context(String vaultId, Tier tier, int epoch, int seq, Uint8List prevHash) =>
      ctx2('tier-export', [vaultId, tier.name, u32be(epoch), u32be(seq), prevHash]);

  /// Hash that becomes the next export's `prevHash` (and the manifest head).
  static Uint8List hash(Uint8List ciphertext) => sha256Of(ciphertext);

  static Future<TierExport> seal({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required int epoch,
    required int seq,
    required Uint8List prevHash,
    required Uint8List plaintext,
  }) async {
    final header = TierExportHeader(epoch: epoch, seq: seq, prevHash: prevHash);
    final ct = await Aead.seal(tierKey, plaintext,
        type: ObjectType.tierExport,
        context: context(vaultId, tier, header.epoch, header.seq, header.prevHash));
    return TierExport(header, ct);
  }

  static Future<Uint8List> open({
    required String vaultId,
    required Tier tier,
    required Uint8List tierKey,
    required TierExportHeader header,
    required Uint8List ciphertext,
  }) =>
      Aead.open(tierKey, ciphertext,
          type: ObjectType.tierExport,
          context: context(vaultId, tier, header.epoch, header.seq, header.prevHash));
}
