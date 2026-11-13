/// Device-held freshness anchor (SSB-2026-002, design D6/D7).
///
/// The vault manifest carries a monotonic sequence number `seq`, bumped on
/// every write. A [FreshnessAnchor] remembers, per vault, the highest `seq`
/// this device has accepted; `VaultKeyring.open` / `fromVaultKey` refuse a
/// manifest whose `seq` is below it, so a server (or a restored backup)
/// cannot roll the vault back to a state that re-admits a revoked tier key
/// or a deleted item.
///
/// Write order matters: the app writes the vault file first, THEN calls
/// `VaultKeyring.commitManifest()` (which calls [commit]). A crash between
/// the two leaves the anchor one step behind, which the next open simply
/// catches up; the reverse order could lock the owner out of their own file.
///
/// A missing anchor (new device, cleared storage) is NOT a failure: the
/// manifest is accepted, committed, and the keyring reports
/// `restoredWithoutAnchor` so the app can offer a rotation. On the web the
/// anchor lives in `localStorage`, which the user (or an XSS) can clear; that
/// weakness is documented in CRYPTO-DESIGN and is why Phase 2 adds an
/// owner-signed manifest head.
abstract class FreshnessAnchor {
  /// Highest manifest `seq` accepted for [vaultId] on this device, or null
  /// when nothing has been recorded yet.
  Future<int?> lastSeq(String vaultId);

  /// Records [seq] as accepted for [vaultId]. Implementations should never
  /// move the value backwards; `VaultKeyring` only calls this with a value
  /// >= the current one.
  Future<void> commit(String vaultId, int seq);

  /// Hex SHA-256 of the manifest blob accepted at [lastSeq], or null when
  /// none is recorded (no anchor, or a seq-only anchor written before the
  /// head hash existed). `seq` is per keyring, so two devices (or a server
  /// replaying a sibling write) can legitimately produce different manifests
  /// with the SAME seq; the hash is what tells them apart. With only `seq`,
  /// a replayed equal-seq manifest would be accepted and could silently undo
  /// a revocation.
  Future<String?> lastHash(String vaultId);

  /// Records [seq] together with the hex SHA-256 [manifestHash] of the
  /// manifest blob. Never moves backwards. At an equal [seq] it only fills in
  /// a missing hash (upgrade of a seq-only anchor); it never replaces one.
  Future<void> commitHead(String vaultId, int seq, String manifestHash);
}

/// Process-local anchor for tests and for the owner-side CLI tools. The app
/// uses its own `DeviceAnchor` (secure storage / localStorage).
class InMemoryAnchor implements FreshnessAnchor {
  final Map<String, int> _seq = {};
  final Map<String, String> _hash = {};

  /// Every commit, in order, for assertions on write-then-commit ordering.
  final List<(String vaultId, int seq)> commits = [];

  @override
  Future<int?> lastSeq(String vaultId) async => _seq[vaultId];

  @override
  Future<void> commit(String vaultId, int seq) async {
    final cur = _seq[vaultId];
    if (cur == null || seq > cur) {
      _seq[vaultId] = seq;
      _hash.remove(vaultId); // a bare seq carries no hash for the new head
    }
    commits.add((vaultId, seq));
  }

  @override
  Future<String?> lastHash(String vaultId) async => _hash[vaultId];

  @override
  Future<void> commitHead(String vaultId, int seq, String manifestHash) async {
    final cur = _seq[vaultId];
    if (cur == null || seq > cur) {
      _seq[vaultId] = seq;
      _hash[vaultId] = manifestHash;
    } else if (seq == cur && _hash[vaultId] == null) {
      _hash[vaultId] = manifestHash;
    }
    commits.add((vaultId, seq));
  }

  /// Simulates a seq-only anchor from before the head hash existed.
  void dropHash(String vaultId) => _hash.remove(vaultId);

  /// Simulates lost device state (new phone, cleared storage).
  void forget(String vaultId) {
    _seq.remove(vaultId);
    _hash.remove(vaultId);
  }
}
