// Shared helpers for the format-v2 (SSB-2026-002) tests: a tiny in-memory
// "vault file" so tests can write, snapshot, replay and reopen without
// repeating the plumbing. Not a test.
import 'dart:convert';
import 'dart:typed_data';

import 'package:ssb_crypto/ssb_crypto.dart';

Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));

/// One written state of a vault, exactly what the app would persist.
class StoredVault {
  final String vaultId;
  final Map<String, Uint8List> wrappedVaultKeys; // slot -> blob
  final Map<String, int> slotEpochs; // cleartext, beside the manifest
  final Uint8List manifest;
  final Map<Tier, Uint8List> tiers;
  final List<SealedItem> items;
  StoredVault(this.vaultId, this.wrappedVaultKeys, this.slotEpochs, this.manifest, this.tiers, this.items);

  /// Reopen through the passphrase/recovery slot path. Every field can be
  /// overridden to simulate a server replaying an older object.
  Future<VaultKeyring> open({
    required Uint8List kek,
    String slot = 'unlock',
    required FreshnessAnchor anchor,
    Uint8List? wrappedVaultKey,
    Map<String, int>? slotEpochs,
    Uint8List? manifest,
    Map<Tier, Uint8List>? tiers,
    List<SealedItem>? items,
    String? vaultId,
  }) =>
      VaultKeyring.open(
        vaultId: vaultId ?? this.vaultId,
        kek: kek,
        slot: slot,
        wrappedVaultKey: wrappedVaultKey ?? wrappedVaultKeys[slot]!,
        slotEpochs: slotEpochs ?? this.slotEpochs,
        manifestBlob: manifest ?? this.manifest,
        wrappedTierKeys: tiers ?? this.tiers,
        items: items ?? this.items,
        anchor: anchor,
      );

  /// Reopen through the biometric (Vault Key) path.
  Future<VaultKeyring> openWithVaultKey({
    required Uint8List vaultKey,
    required FreshnessAnchor anchor,
    Uint8List? manifest,
    Map<Tier, Uint8List>? tiers,
    List<SealedItem>? items,
  }) =>
      VaultKeyring.fromVaultKey(
        vaultId: vaultId,
        vaultKey: vaultKey,
        manifestBlob: manifest ?? this.manifest,
        wrappedTierKeys: tiers ?? this.tiers,
        items: items ?? this.items,
        anchor: anchor,
      );
}

/// The owner's side: a keyring plus the slots it has wrapped. [write]
/// produces a [StoredVault] snapshot (and commits the anchor unless told
/// not to), the way `vault_store.dart` will.
class OwnerVault {
  final VaultKeyring ring;
  final Map<String, Uint8List> wrappedVaultKeys = {};
  OwnerVault(this.ring);

  String get vaultId => ring.vaultId;

  static Future<OwnerVault> create(String vaultId,
      {required FreshnessAnchor anchor, Map<String, Uint8List> keks = const {}}) async {
    final o = OwnerVault(VaultKeyring.create(vaultId, anchor: anchor));
    for (final e in keks.entries) {
      await o.setSlot(e.key, e.value);
    }
    return o;
  }

  /// (Re)wraps the Vault Key for [slot] at the next epoch (create / passphrase change).
  Future<Uint8List> setSlot(String slot, Uint8List kek) async =>
      wrappedVaultKeys[slot] = await ring.wrapVaultKey(kek, slot: slot, epoch: ring.nextSlotEpoch(slot));

  Future<SealedItem> sealItem(Tier t, String id, String text) => ItemCrypto.seal(
      vaultId: vaultId, tier: t, tierKey: ring.tierKey(t), tierEpoch: ring.tierEpoch(t),
      itemId: id, plaintext: bytes(text));

  Future<Uint8List> openItem(SealedItem i) =>
      ItemCrypto.open(vaultId: vaultId, tierKey: ring.tierKey(i.tier), tierEpoch: ring.tierEpoch(i.tier), item: i);

  /// Re-wraps every item of [t] after `ring.rotateTier(t)` (old key/epoch given).
  Future<List<SealedItem>> rewrapAfterRotation(
      List<SealedItem> items, Tier t, Uint8List oldKey, int oldEpoch) async {
    final out = <SealedItem>[];
    for (final i in items) {
      out.add(i.tier != t
          ? i
          : await ItemCrypto.rewrapItemKey(
              vaultId: vaultId, item: i, oldTierKey: oldKey, oldTierEpoch: oldEpoch,
              newTier: t, newTierKey: ring.tierKey(t), newTierEpoch: ring.tierEpoch(t)));
    }
    return out;
  }

  /// Writes the vault: wraps every tier, seals the manifest over [items],
  /// then (write THEN commit) commits the anchor.
  Future<StoredVault> write(List<SealedItem> items,
      {Iterable<String>? beneficiaries, bool commit = true}) async {
    final tiers = {for (final t in Tier.values) t: await ring.wrapTierKey(t)};
    final manifest = await ring.sealManifest(items: items, beneficiaryEntries: beneficiaries);
    if (commit) await ring.commitManifest();
    return StoredVault(vaultId, Map.of(wrappedVaultKeys), Map.of(ring.slotEpochs), manifest, tiers, List.of(items));
  }
}
