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
}

/// Process-local anchor for tests and for the owner-side CLI tools. The app
/// uses its own `DeviceAnchor` (secure storage / localStorage).
class InMemoryAnchor implements FreshnessAnchor {
  final Map<String, int> _seq = {};

  /// Every commit, in order, for assertions on write-then-commit ordering.
  final List<(String vaultId, int seq)> commits = [];

  @override
  Future<int?> lastSeq(String vaultId) async => _seq[vaultId];

  @override
  Future<void> commit(String vaultId, int seq) async {
    final cur = _seq[vaultId];
    if (cur == null || seq > cur) _seq[vaultId] = seq;
    commits.add((vaultId, seq));
  }

  /// Simulates lost device state (new phone, cleared storage).
  void forget(String vaultId) => _seq.remove(vaultId);
}
