# ssb_crypto

Zero-knowledge, hybrid post-quantum crypto core for So Smart Beneficiary.
Design: `../../docs/CRYPTO-DESIGN.md`. Suite v1, object format v2 (see below):

| Job | Algorithm | Verified by |
|---|---|---|
| Hybrid KEM | X-Wing (ML-KEM-768 + X25519) | draft-connolly-cfrg-xwing-kem-10 Appendix C vectors (all 3) |
| Public-key encryption | HPKE RFC 9180 base mode, X-Wing / HKDF-SHA256 / AES-256-GCM | RFC 9180 key-schedule + encryption vector |
| Data | AES-256-GCM, per-item keys, versioned header + epoch-bound length-prefixed context in AAD | tamper/downgrade/type-confusion/v1-v2 confusion tests |
| Files | STREAM (64 KiB chunks) | truncation/extension/reorder tests |
| KDF | HKDF-SHA-384 | independent Python computation |
| Passphrase | Argon2id (128 MiB, t=3) + 128-bit Secret Key | RFC 9106 §5.3 vector |
| Release split | Shamir 2-of-3, GF(2^8), constant-time field ops; shares carry epoch + salted 128-bit check; secrets must be uniformly random, >= 16 bytes | recover/insufficient/mismatch/cross-epoch tests |
| Key verification | Safety numbers (5200× SHA-512) | determinism/sensitivity tests |

Also implemented: ML-DSA-65 + Ed25519 hybrid signatures (`signature.dart`) and Unicode NFKD passphrase
normalization (`unlock.dart`).

**What this package is and is not (current truth).** Everything except ML-KEM and ML-DSA is pure Dart
(`cryptography` 2.9.0 Dart backend, no libsodium; one exception: the app may swap X-Wing's X25519 key
agreement for Apple CryptoKit through `XWing.installX25519`, which installs a backend only after RFC 7748 +
Dart cross-checks pass): AES-256-GCM, HKDF, Argon2id,
X25519, Ed25519 and SHA-2 are correct and vector-tested but NOT hardware-accelerated and NOT guaranteed
constant-time (Dart AES/GHASH are table/branch based). ML-KEM-768 and ML-DSA-65 are native C via the
vendored PQ Code Package wrappers in `third_party/`. Wiping secrets from memory is best-effort only: `wipe()`
zeroes the buffers this code owns, but Dart's GC may have copied them first. Not built yet (roadmap, see
`../../docs/CRYPTO-DESIGN.md` §4): native or platform AES/Argon2/Ed25519 (and X25519 off Apple), native secret storage, and
Secure Enclave / StrongBox key storage.

Run: `dart test` (needs a C toolchain; the ML-KEM native code builds automatically).
Vendored native wrappers and the security fixes applied: `third_party/mlkem_native/SSB_PATCHES.md`,
`third_party/mldsa_native/SSB_PATCHES.md`.

Shamir note: the polynomial shares are information-theoretic, but each share also carries a 16-byte
salted HKDF tag of the secret (`HKDF-SHA384(secret, salt, 'ssb/v2/share-check' || u16(epoch))[:16]`, one
8-byte salt per split) to detect mismatched/corrupt shares and to bind the key generation. One share
therefore lets an attacker confirm a guess of a LOW-ENTROPY secret, so `Shamir.split` only accepts secrets
of at least 16 bytes and callers must pass uniformly random keys (the tier keys are 256-bit random).

## Format v2 (SSB-2026-002, freshness)

Every stored object now says which **key generation** it belongs to, and a sealed **manifest** says which
generation is current. A server that replays an older wrapped key, slot, item, export or manifest is
refused instead of silently rolling the vault back. Design: `../../docs/CRYPTO-DESIGN.md` §2a.

Header byte 3 (`Suite.formatVersion`) is `2`. `Aead.open` / `StreamCipher.decrypt` accept only v2;
v1 objects open only through `Aead.openLegacyV1` / `StreamCipher.decryptLegacyV1` and the classes in
`package:ssb_crypto/legacy_v1.dart` (not exported from `ssb_crypto.dart`), which exist for the one-time
v1 -> v2 migration.

**Contexts** are built with `ctx2(what, fields)` = `'ssb/v2/' || lp(what) || fields`, where strings are
length-prefixed (`u32be(len) || utf8`) and integers are passed through an explicit width helper
(`u16be`, `u32be`), so no two field lists encode alike:

| Object | `ObjectType` | AAD context |
|---|---|---|
| Vault Key under an unlock/recovery key | `wrappedKey` | `ctx2('vk', [vaultId, slot, u32(slotEpoch)])` |
| Tier key under the Vault Key | `wrappedKey` | `ctx2('tk', [vaultId, tier, u32(tierEpoch)])` |
| Manifest under the Vault Key | `manifest` (0x05) | `ctx2('manifest', [vaultId])` |
| Item key under the tier key | `wrappedKey` | `ctx2('ik', [vaultId, tier, u32(tierEpoch), itemId])` |
| Item body under the item key | `item` | `ctx2('item', [vaultId, itemId])` |
| File stream under the file key | `fileStream` | `ctx2('file', [vaultId, fileId])` |
| Tier export under the tier key | `tierExport` (0x06) | `ctx2('tier-export', [vaultId, tier, u32(epoch), u32(seq), prevHash(32)])` |

Non-AEAD labels: S2 HPKE info `'ssb/v2/s2' || lp(vaultId) || lp(beneficiaryId) || lp(tier) || u16(epoch)`;
signatures `'ssb/v2/sig' || u16(len(purpose)) || purpose || message`; Shamir check `'ssb/v2/share-check' || u16(epoch)`;
set hashes `'ssb/v2/items-hash'` / `'ssb/v2/beneficiary-set'`. Kit codes: `SSB2-BK` (beneficiary, S1),
`SSB2-AK` (attorney, S3), each a 61-byte v2 share; `SSB1-SK` / `SSB1-RK` (Secret Key / Recovery Key) are
unchanged. The kit checksum (`KitCode`) is label-bound, so a v1 kit is rejected at decode.

**Manifest** (`VaultManifest`): canonical sorted-key JSON `{v:2, vaultId, seq, tierEpochs, slotEpochs,
slotHashes, tierExportSeq, tierExportHead, itemsHash, beneficiarySetHash}`. `VaultKeyring.open` checks, in
order: Vault Key (slot context with the cleartext slot epoch) -> manifest -> slot epoch and slot hash ->
`seq >= FreshnessAnchor.lastSeq(vaultId)` -> every tier key under its epoch -> `itemsHash` of the items.
The app calls `sealManifest()` on every write (seq + 1), writes the file, then `commitManifest()`.
A missing anchor (new device) is accepted and reported via `restoredWithoutAnchor`.

**Epochs**: tier epochs start at 1 and `rotateTier` bumps them; kits carry the epoch (u16) and
`Release.recover*` return `(key, epoch)`, failing with `'kit from an older key generation'` when the two
shares disagree. Slot epochs start at 1; 0 marks a recovery slot still wrapped in v1 by the migration
(`recordLegacySlot`), opened once through the v1 context and then re-wrapped.

Known residuals (documented, Phase 2): the web anchor lives in `localStorage`; a first-time beneficiary
with no prior `seq` cannot detect a same-epoch export rollback until the owner-signed manifest head
exists; `HybridSignature` and the claim/owner tokens carry no freshness of their own
(`test/freshness_regression_test.dart` F5/F6).
