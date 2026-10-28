import 'dart:convert';
import 'dart:typed_data';

import 'aead.dart';
import 'bytes.dart';
import 'suite.dart';
import 'vault.dart';

/// The sealed vault manifest (SSB-2026-002, design D5).
///
/// One small JSON document, canonical (keys sorted at every level, no
/// whitespace), sealed under the Vault Key with [ObjectType.manifest] and
/// context `ctx2('manifest', [vaultId])`. It is the authority on what the
/// CURRENT state of the vault is:
///
/// ```
/// {
///   "v": 2,
///   "vaultId": "...",
///   "seq": u32,                       // bumped on every write; anchored per device
///   "tierEpochs": {"ice": n, "essentials": n, "secrets": n},
///   "slotEpochs": {"unlock": n, "recovery": n},   // 0 = still a v1 wrap (migration)
///   "slotHashes": {"unlock": hex, "recovery": hex}, // sha256 of each wrapped Vault Key blob
///   "tierExportSeq": {"essentials": n, ...},        // latest export sequence per tier
///   "tierExportHead": {"essentials": hex, ...},     // sha256 of the latest export ciphertext
///   "itemsHash": hex,                 // see [computeItemsHash]
///   "beneficiarySetHash": hex         // see [computeBeneficiarySetHash]
/// }
/// ```
///
/// `VaultKeyring.open` opens the Vault Key, then this, then checks every
/// other stored object against it: a replayed slot wrap, an old tier-key
/// wrap, a pre-edit item or an older manifest is refused instead of
/// silently accepted (findings F2a/F3/F4).
class VaultManifest {
  static const version = 2;
  static const maxU32 = 0xffffffff;
  static const _hexLen = 64;

  final String vaultId;

  /// Monotonic write counter. Compared against the device's [FreshnessAnchor].
  final int seq;

  /// Key generation of each tier (every tier present).
  final Map<Tier, int> tierEpochs;

  /// Key generation of each Vault-Key slot wrap (`unlock`, `recovery`).
  /// 0 means the slot is still a format-v1 wrap awaiting upgrade.
  final Map<String, int> slotEpochs;

  /// Hex SHA-256 of each slot's wrapped Vault Key blob.
  final Map<String, String> slotHashes;

  /// Latest tier-export sequence per tier (absent = never exported).
  final Map<Tier, int> tierExportSeq;

  /// Hex SHA-256 of the latest tier-export ciphertext per tier.
  final Map<Tier, String> tierExportHead;

  /// Hex [computeItemsHash] of the stored item set.
  final String itemsHash;

  /// Hex [computeBeneficiarySetHash] of the enrolled beneficiaries.
  final String beneficiarySetHash;

  VaultManifest({
    required this.vaultId,
    required this.seq,
    required Map<Tier, int> tierEpochs,
    required Map<String, int> slotEpochs,
    required Map<String, String> slotHashes,
    required Map<Tier, int> tierExportSeq,
    required Map<Tier, String> tierExportHead,
    required this.itemsHash,
    required this.beneficiarySetHash,
  })  : tierEpochs = Map.unmodifiable(tierEpochs),
        slotEpochs = Map.unmodifiable(slotEpochs),
        slotHashes = Map.unmodifiable(slotHashes),
        tierExportSeq = Map.unmodifiable(tierExportSeq),
        tierExportHead = Map.unmodifiable(tierExportHead) {
    _validate();
  }

  void _validate() {
    bool u32(int v) => v >= 0 && v <= maxU32;
    bool hex(String h) => h.length == _hexLen && RegExp(r'^[0-9a-f]+$').hasMatch(h);
    if (!u32(seq) || !hex(itemsHash) || !hex(beneficiarySetHash)) {
      throw const SsbCryptoException('bad manifest');
    }
    for (final t in Tier.values) {
      final e = tierEpochs[t];
      if (e == null || !u32(e)) throw const SsbCryptoException('bad manifest');
    }
    for (final e in slotEpochs.values) {
      if (!u32(e)) throw const SsbCryptoException('bad manifest');
    }
    for (final h in slotHashes.values) {
      if (!hex(h)) throw const SsbCryptoException('bad manifest');
    }
    for (final e in tierExportSeq.values) {
      if (!u32(e)) throw const SsbCryptoException('bad manifest');
    }
    for (final h in tierExportHead.values) {
      if (!hex(h)) throw const SsbCryptoException('bad manifest');
    }
  }

  VaultManifest copyWith({
    int? seq,
    Map<Tier, int>? tierEpochs,
    Map<String, int>? slotEpochs,
    Map<String, String>? slotHashes,
    Map<Tier, int>? tierExportSeq,
    Map<Tier, String>? tierExportHead,
    String? itemsHash,
    String? beneficiarySetHash,
  }) =>
      VaultManifest(
        vaultId: vaultId,
        seq: seq ?? this.seq,
        tierEpochs: tierEpochs ?? this.tierEpochs,
        slotEpochs: slotEpochs ?? this.slotEpochs,
        slotHashes: slotHashes ?? this.slotHashes,
        tierExportSeq: tierExportSeq ?? this.tierExportSeq,
        tierExportHead: tierExportHead ?? this.tierExportHead,
        itemsHash: itemsHash ?? this.itemsHash,
        beneficiarySetHash: beneficiarySetHash ?? this.beneficiarySetHash,
      );

  // ---- canonical JSON ----------------------------------------------------

  Map<String, Object> toJson() => {
        'v': version,
        'vaultId': vaultId,
        'seq': seq,
        'tierEpochs': {for (final e in tierEpochs.entries) e.key.name: e.value},
        'slotEpochs': Map<String, Object>.from(slotEpochs),
        'slotHashes': Map<String, Object>.from(slotHashes),
        'tierExportSeq': {for (final e in tierExportSeq.entries) e.key.name: e.value},
        'tierExportHead': {for (final e in tierExportHead.entries) e.key.name: e.value},
        'itemsHash': itemsHash,
        'beneficiarySetHash': beneficiarySetHash,
      };

  /// Canonical bytes: keys sorted at every level, no whitespace, UTF-8.
  Uint8List encode() => utf8Bytes(canonicalJson(toJson()));

  /// Recursively sorts map keys and encodes with `dart:convert` (which keeps
  /// insertion order and emits no whitespace), so equal manifests always
  /// encode to identical bytes.
  static String canonicalJson(Object? v) => jsonEncode(_sorted(v));

  static Object? _sorted(Object? v) {
    if (v is Map) {
      final keys = v.keys.map((k) => k as String).toList()..sort();
      return {for (final k in keys) k: _sorted(v[k])};
    }
    if (v is List) return [for (final e in v) _sorted(e)];
    return v;
  }

  /// Strict decoder: every field present with the right type and range,
  /// no unknown keys, every tier in `tierEpochs`. Anything else is
  /// [SsbCryptoException] `bad manifest` (never a cast error).
  factory VaultManifest.fromJson(Map<String, dynamic> j) {
    const keys = {
      'v', 'vaultId', 'seq', 'tierEpochs', 'slotEpochs', 'slotHashes',
      'tierExportSeq', 'tierExportHead', 'itemsHash', 'beneficiarySetHash',
    };
    if (j.keys.toSet().length != keys.length || !j.keys.every(keys.contains)) {
      throw const SsbCryptoException('bad manifest');
    }
    if (j['v'] != version) throw const SsbCryptoException('bad manifest');
    final vaultId = j['vaultId'], seq = j['seq'];
    final itemsHash = j['itemsHash'], benHash = j['beneficiarySetHash'];
    if (vaultId is! String || seq is! int || itemsHash is! String || benHash is! String) {
      throw const SsbCryptoException('bad manifest');
    }
    Map<String, int> intMap(Object? m) {
      if (m is! Map) throw const SsbCryptoException('bad manifest');
      final out = <String, int>{};
      for (final e in m.entries) {
        final k = e.key, v = e.value;
        if (k is! String || v is! int) throw const SsbCryptoException('bad manifest');
        out[k] = v;
      }
      return out;
    }
    Map<String, String> strMap(Object? m) {
      if (m is! Map) throw const SsbCryptoException('bad manifest');
      final out = <String, String>{};
      for (final e in m.entries) {
        final k = e.key, v = e.value;
        if (k is! String || v is! String) throw const SsbCryptoException('bad manifest');
        out[k] = v;
      }
      return out;
    }
    Tier tier(String name) {
      for (final t in Tier.values) {
        if (t.name == name) return t;
      }
      throw const SsbCryptoException('bad manifest');
    }
    final tierEpochs = intMap(j['tierEpochs']);
    final tierExportSeq = intMap(j['tierExportSeq']);
    final tierExportHead = strMap(j['tierExportHead']);
    return VaultManifest(
      vaultId: vaultId,
      seq: seq,
      tierEpochs: {for (final e in tierEpochs.entries) tier(e.key): e.value},
      slotEpochs: intMap(j['slotEpochs']),
      slotHashes: strMap(j['slotHashes']),
      tierExportSeq: {for (final e in tierExportSeq.entries) tier(e.key): e.value},
      tierExportHead: {for (final e in tierExportHead.entries) tier(e.key): e.value},
      itemsHash: itemsHash,
      beneficiarySetHash: benHash,
    );
  }

  factory VaultManifest.decode(Uint8List bytes) {
    final Object? j;
    try {
      j = jsonDecode(utf8.decode(bytes));
    } catch (_) {
      throw const SsbCryptoException('bad manifest');
    }
    if (j is! Map<String, dynamic>) throw const SsbCryptoException('bad manifest');
    return VaultManifest.fromJson(j);
  }

  // ---- sealing -----------------------------------------------------------

  static List<int> context(String vaultId) => ctx2('manifest', [vaultId]);

  /// Seals [manifest] under [vaultKey] (AES-256-GCM, [ObjectType.manifest]).
  static Future<Uint8List> seal(Uint8List vaultKey, VaultManifest manifest) =>
      Aead.seal(vaultKey, manifest.encode(),
          type: ObjectType.manifest, context: context(manifest.vaultId));

  /// Opens a sealed manifest and checks it is for [vaultId] (the context
  /// already binds it; the explicit check makes the contract visible).
  static Future<VaultManifest> open(Uint8List vaultKey, Uint8List blob,
      {required String vaultId}) async {
    final pt = await Aead.open(vaultKey, blob,
        type: ObjectType.manifest, context: context(vaultId));
    final m = VaultManifest.decode(pt);
    if (m.vaultId != vaultId) throw const SsbCryptoException('bad manifest');
    return m;
  }

  // ---- set hashes --------------------------------------------------------

  /// SHA-256 over the item set, order-independent:
  ///
  ///     'ssb/v2/items-hash' || u32(count) || for each item sorted by
  ///     (itemId, tier, wrappedItemKey): lp(itemId) || lp(tier) || u32(len) || wrappedItemKey
  ///
  /// Binds which items exist, in which tier, under which (fresh per seal)
  /// item-key wrap. A server that serves a pre-edit item, a deleted item or
  /// a pre-rewrap item changes this hash and the open fails (F2a/F2b). The
  /// body is bound transitively: it only opens under the item key inside
  /// `wrappedItemKey`, so a swapped body fails on its own.
  static Uint8List computeItemsHash(Iterable<SealedItem> items) {
    final rows = [
      for (final i in items)
        (key: '${i.itemId}\u0000${i.tier.name}\u0000${hexEncode(i.wrappedItemKey)}', item: i)
    ]..sort((a, b) => a.key.compareTo(b.key));
    final parts = <List<int>>[utf8Bytes('ssb/v2/items-hash'), u32be(rows.length)];
    for (final r in rows) {
      parts
        ..add(lengthPrefixed(r.item.itemId))
        ..add(lengthPrefixed(r.item.tier.name))
        ..add(u32be(r.item.wrappedItemKey.length))
        ..add(r.item.wrappedItemKey);
    }
    return sha256Of(concatBytes(parts));
  }

  /// Hex form of [computeItemsHash], as stored in the manifest.
  static String itemsHashHex(Iterable<SealedItem> items) => hexEncode(computeItemsHash(items));

  /// SHA-256 over the set of enrolled beneficiaries, order-independent,
  /// duplicates collapsed:
  ///
  ///     'ssb/v2/beneficiary-set' || u32(count) || lp(entry) ...  (entries sorted)
  ///
  /// The app decides what an entry is; the beneficiary id alone detects a
  /// hidden removal or addition (audit A2). Richer entries (id + kit epoch +
  /// public-key hash) bind more and are encouraged.
  static Uint8List computeBeneficiarySetHash(Iterable<String> entries) {
    final sorted = entries.toSet().toList()..sort();
    return sha256Of(concatBytes([
      utf8Bytes('ssb/v2/beneficiary-set'),
      u32be(sorted.length),
      for (final e in sorted) lengthPrefixed(e),
    ]));
  }

  static String beneficiarySetHashHex(Iterable<String> entries) =>
      hexEncode(computeBeneficiarySetHash(entries));
}
