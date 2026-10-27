# So Smart Beneficiary: cryptographic design

Extract of the crypto sections of the product spec. Business, pricing and operations sections are omitted. Status: **not independently audited.** Describes object format v2 (section 2a). Where the text describes hardware-backed or native primitives, that is the roadmap; the code today is pure Dart (see the package README).


## 1. Principles

1. **Zero-knowledge.** So Smart Apps servers never hold enough to decrypt a vault, even if breached, subpoenaed, or run by a rogue insider.
2. **Post-quantum from day one.** A vault is written today and may be opened in 20–40 years. Anyone who copies encrypted data now can store it and decrypt it once quantum computers mature ("harvest now, decrypt later"). So every public-key operation is **hybrid**: a proven classical algorithm *plus* a NIST post-quantum algorithm. It stays secure as long as either one holds.
3. **Standards only, no homemade crypto.** NIST FIPS 197 (AES), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA); IETF RFC 9180 (HPKE), RFC 9106 (Argon2), RFC 5869 (HKDF), X-Wing (IETF CFRG hybrid KEM).
4. **Crypto agility.** Every ciphertext and wrapped key carries a versioned suite ID. When standards move, keys are re-wrapped without re-encrypting every file.
5. **Hardware-backed keys.** *Planned, not built yet.* Private keys are meant to live in Secure Enclave (iOS) / StrongBox (Android) wherever the platform allows. Today every key is held in app memory and stored wrapped under the Unlock Key; no key lives in secure hardware.

## 2. Cipher suite v1

| Job | Algorithm | Why |
|---|---|---|
| Encrypting items and files | **AES-256-GCM**, a unique random 256-bit key per item/file (envelope encryption); files in 64 KiB chunks with chunk index + final-chunk flag in the AAD | FIPS-approved algorithm; 256-bit keys stay strong against quantum attacks; chunking blocks truncation and reordering |
| Key hierarchy | Vault Key → Tier Keys (T0/T1/T2) → per-item keys, each wrapped with AES-256-GCM under a length-prefixed, epoch-bound context (section 2a); derivations via **HKDF-SHA-384** | Compromise of one item key exposes one item; tiers map to release rules |
| Owner passphrase | **Argon2id** (RFC 9106), calibrated per device (target ≥ 128 MiB memory, ~0.5–1 s) | Memory-hard; the current OWASP first choice against GPU cracking |
| Second secret | **128-bit Account Secret Key**, generated on device, mixed with the passphrase via HKDF, printed in the Emergency Kit | A stolen server database can't be brute-forced even with a weak passphrase (same model as 1Password) |
| Sharing with beneficiaries | **HPKE (RFC 9180) with X-Wing KEM = ML-KEM-768 + X25519** | Hybrid post-quantum; native in Apple CryptoKit (iOS 26+) |
| Signatures (enrollment, release tokens, audit log) | **Ed25519 + ML-DSA-65** (hybrid, both must verify) | Server-issued release tokens and audit entries can't be forged, now or post-quantum |
| Beneficiary release split | **Shamir 2-of-3 over GF(256)**, each share with the key generation (epoch) and a salted integrity tag (so secrets must be uniformly random, >= 16 bytes: one share lets an attacker confirm a guess of a low-entropy secret) | Security doesn't depend on computing power, so quantum computers don't affect it |
| App login | **Passkeys** (WebAuthn/FIDO2) for owners and beneficiaries; the vault passphrase never leaves the device | Phishing-resistant; account login and vault decryption are separate |
| Transport | TLS 1.3, hybrid PQ key exchange (X25519MLKEM768) where supported | Defense in depth only; security never depends on it |

**Implementation status today (read this before relying on the table above).** The AES-256-GCM, HKDF, Argon2id, X25519, Ed25519 and SHA-2 code in `packages/ssb_crypto` is **pure Dart** (`cryptography` 2.9.0 in its Dart backend; no `cryptography_flutter`, no libsodium, no CryptoKit). It is correct and covered by test vectors, but it is **not hardware-accelerated and not guaranteed constant-time**: Dart's AES and GHASH are table/branch based and can leak through timing and cache side channels to an attacker who can run code on the same device. Only ML-KEM and ML-DSA run as native C (the vendored PQ Code Package wrappers in `third_party/`). Secrets cannot be reliably wiped from Dart memory: the code zeroes buffers it owns on a best-effort basis (`wipe()`), but Dart's garbage collector may already have copied them. *Roadmap:* move AES-GCM, HKDF, Argon2id, X25519 and Ed25519 to native or platform primitives (CryptoKit, libsodium, platform crypto, per §6.4), keep secrets in native memory, and use Secure Enclave / StrongBox; this is a pre-launch item tracked with the independent audit in §6.5.

**Passphrase normalization.** The passphrase is Unicode **NFKD**-normalized before Argon2id (`Unlock.normalizePassphrase`), so the same passphrase typed on different keyboards/IMEs (precomposed vs combining accents, full-width Latin, ligatures, no-break spaces) derives the same Unlock Key. ASCII is unaffected, so ASCII passphrases derive the same keys as before. Vaults sealed before normalization shipped (2026-09) open through `Unlock.openWithPassphrase`, which tries the normalized key first and, only when NFKD changes the passphrase, retries once with the raw form. The unlock slot is not re-wrapped automatically; any future passphrase-change or re-wrap flow must seal with `Unlock.deriveUnlockKey` (normalized). Normalization tables come from `unorm_dart` 0.3.2 (pinned) — NFKD is stable for assigned code points under Unicode's normalization stability policy, so upgrading the table cannot change keys for characters it already covers.

## 2a. Object format v2: contexts, epochs, manifest, freshness

Format v2 (header byte 3 = `2`; suite id unchanged at v1) replaced the original ad-hoc authenticated-data strings and added freshness. It was released as one change that closes SSB-2026-002, -003 and -004 (see `SECURITY-FIXES.md`).

**Contexts (`ctx2`).** Every AEAD context is `'ssb/v2/' || lp(what) || field_1 || ... || field_n`. Strings and byte fields are length-prefixed (`lp` = 4-byte big-endian length, then the bytes); integers go through explicit fixed-width encoders (`u16be`, `u32be`) that refuse out-of-range values instead of truncating them. Because every variable-width field carries its length, two different field lists can never encode to the same bytes. The v1 contexts joined fields with `|` (for example `ssb/v1/ik|vault:V|tier:ice|item:I`), so an id containing `|` could make two different tuples collide (SSB-2026-004). The objects and their contexts:

| Object | Context |
|---|---|
| Vault Key under an unlock or recovery key | `ctx2('vk', [vaultId, slot, u32(slotEpoch)])` |
| Tier key under the Vault Key | `ctx2('tk', [vaultId, tier, u32(tierEpoch)])` |
| Manifest under the Vault Key | `ctx2('manifest', [vaultId])` |
| Item key under the tier key | `ctx2('ik', [vaultId, tier, u32(tierEpoch), itemId])` |
| Item body / file stream | `ctx2('item', [vaultId, itemId])` / `ctx2('file', [vaultId, fileId])` |
| Tier export | `ctx2('tier-export', [vaultId, tier, u32(epoch), u32(seq), prevHash])` |

The ciphertext header (magic, format version, suite, object type) is also part of the authenticated data, so a v1 object cannot be presented as v2 or an item as a manifest. `Aead.open` and the stream cipher accept format v2 only.

**Key generations (epochs).** Each tier has a `u32` epoch, starting at 1 and incremented by every tier-key rotation. The epoch is bound into the tier-key wrap, every item-key wrap and every tier export. The two Vault-Key slots (unlock and recovery) carry their own slot epoch, bound into the slot wrap. Beneficiary shares carry the epoch too: a v2 share is `version(1)=2 | threshold(1) | x(1) | epoch(2) | salt(8) | keyCheck(16) | y(32)` = 61 bytes, where `keyCheck = HKDF-SHA-384(ikm = secret, salt = salt, info = 'ssb/v2/share-check' || u16(epoch))[0..16]`, and the server's S2 HPKE info ends in the epoch. A Beneficiary Kit from before a rotation therefore fails to combine with a newer S2 ("kit from an older key generation") instead of yielding a revoked key. Kit labels are `SSB2-BK` and `SSB2-AK`; the kit checksum is label-bound, so a v1 kit is rejected at decode.

**The sealed manifest.** One small canonical JSON document (keys sorted, no whitespace), sealed under the Vault Key, states what the current vault is: `{v:2, vaultId, seq, tierEpochs, slotEpochs, slotHashes, tierExportSeq, tierExportHead, itemsHash, beneficiarySetHash}`. `slotHashes` are SHA-256 of each stored wrapped Vault Key; `itemsHash` is a hash over every item's id, tier and wrapped item key (the body is bound through the item key it only opens under); `tierExportHead` is the hash of the latest export per tier. Opening a vault checks, in order: the Vault Key (slot context with its epoch), the manifest, the slot's epoch and hash, `seq` against the device anchor, every tier key under its manifest epoch, and finally `itemsHash` against the stored items. A replayed old slot, an old tier-key wrap, a pre-edit item or an older manifest each fails one of these checks.

**The freshness anchor.** The manifest has a monotonic `seq`, bumped on every write. Each device remembers the highest `seq` it has accepted for a vault (a `FreshnessAnchor`; the app keeps it in platform secure storage, or `localStorage` on the web) and refuses any manifest below it. The app writes the vault file first and commits the anchor afterwards, so a crash can leave the anchor one step behind (which the next open catches up) but never ahead of the file. A device with no anchor (new phone, cleared storage) accepts the manifest and reports that it was restored without one, so the app can offer a key rotation. Consequences stated plainly: the web anchor can be cleared by the user or by script injection, and a device that has never seen the vault cannot by itself tell a rolled-back manifest from the current one at the same epoch; an owner-signed manifest head is planned to close that.

**Tier export chain.** Each tier's server-held export is sealed under the tier key with `(epoch, seq, prevHash)` in its authenticated data, and its cleartext header repeats them. `seq` increases by one per export and `prevHash` is the hash of the previous export, so the exports form a chain. Calls for one tier are serialised, and the key, epoch and plaintext are snapshotted before the first `await`, so two overlapping pushes cannot fork the chain. The app's beneficiary recovery path (not in this repository) refuses an export from an older epoch than the Kit's, flags one from a newer epoch (the Kit is outdated), and warns if the sequence it has seen for a tier goes backwards.

**Legacy v1 read paths.** Vaults and Kits created before format v2 still exist, so the v1 read code is kept in `legacy_v1.dart`, exported separately as `package:ssb_crypto/legacy_v1.dart` and not from the main library. It is open-only: it contains no seal operations, and its only job is to open a v1 object once so the contents can be re-sealed in v2 (vault migration rotates every tier key and re-seals every item; a v1 beneficiary export is opened to tell the beneficiary to request a new Kit). The old `|` delimiter encodings are preserved byte for byte there because they must reproduce what was sealed years earlier. They remain open-only and are reachable only through keys already authenticated by the vault they belong to, so no attacker-chosen identifier pair can be steered into a collision; tests pin both facts (`test/legacy_v1_test.dart`, `test/redteam_injectivity_test.dart`).

**Owner identity (SSB-2026-003, crypto part).** A vault id can be self-certifying: the owner derives an Ed25519 key from the Vault Key (`HKDF-SHA-384`, info `ssb/v2/owner-sign`) and the id is `v2_` plus the first 20 bytes (40 hex characters) of `SHA-256('ssb/v2/vault-id' || publicKey)`. The id is therefore bound to the key by construction, and proving ownership means signing a server challenge, `purpose || lp(vaultId) || u16(len(nonce)) || nonce`, with that key (purposes `ssb/v2/owner-auth` and `ssb/v2/owner-delete` are distinct). See `owner_identity.dart` and the known-answer vector in `test/vectors/owner_identity_kat.json`. Only the Ed25519 leg exists today.

## 3. Two-key release

| Share | Held by | Purpose |
|---|---|---|
| **S1** | Beneficiary, in their printed **Beneficiary Kit** (QR) | Useless alone |
| **S2** | Server, **HPKE-sealed to the beneficiary's X-Wing public key**; withheld until the timer releases | Server can't read it; beneficiary can't get it early |
| **S3** (optional) | Attorney / sealed envelope / safe deposit box (QR) | Continuity if So Smart Apps no longer exists |

- Normal path: S1 + S2 after the wait. Company-gone path: S1 + S3 with the open-source **offline recovery tool**.
- **Key-substitution defense:** a malicious server could swap in its own "beneficiary" public key at enrollment. To block that, the owner verifies the beneficiary's key **in person** by scanning a safety-number QR code on the beneficiary's device (same idea as Signal safety numbers). Unverified beneficiaries are flagged in red.

## 4. Implementation

*Status: the list below is the **target** design. Current code is pure Dart plus vendored native ML-KEM/ML-DSA only; see "Implementation status today" in §6.2.*

- **iOS (planned):** Apple CryptoKit (AES-GCM, HKDF, X-Wing HPKE, ML-DSA, Secure Enclave) through a thin platform channel
- **Android / desktop (partly built):** `mlkem_native` and `mldsa_native` are in; libsodium and platform AES are planned. The target is `mlkem_native` (Flutter FFI wrapper around the PQ Code Package's mlkem-native) + libsodium (`sodium_libs`) for X25519/Ed25519/Argon2id; ML-DSA from the same PQ Code Package lineage or liboqs; AES-GCM from platform crypto
- **Web survivor portal:** the same C code compiled to WebAssembly, so every platform runs the same code
- **Cross-platform known-answer tests:** every platform must decrypt every other platform's fixtures (NIST ACVP vectors + X-Wing draft vectors) in CI before merge
- **Memory hygiene:** *today:* best-effort zeroing of Dart buffers only; Dart's garbage collector can't reliably wipe secrets. *Planned:* secrets stay in native memory (libsodium secure allocation) where possible
- **Device hardening:** screenshot and screen-recording block on secret screens, clipboard auto-clear, jailbreak/root warning
- **Metadata:** titles, categories, and file names are encrypted; file sizes are padded to buckets to limit what size reveals
- **FIPS path:** every algorithm except Argon2id and X25519 is FIPS-approved. If an agency or DoD contract requires a FIPS 140-3 validated build, that build swaps Argon2id → PBKDF2 and adds a CNSA 2.0 suite (ML-KEM-1024 / ML-DSA-87), using the suite ID from §6.1

## 5. Threat model (top 6)

| Threat | Mitigation |
|---|---|
| Ex or relative falsely claims death | Wait period, deny alerts on every channel, Tier 2 never skips the wait |
| Server breach | Zero-knowledge; Secret Key blocks offline cracking; S2 sealed to the beneficiary |
| Server swaps a beneficiary key | In-person safety-number verification |
| Harvest now, decrypt later (quantum) | Hybrid ML-KEM/ML-DSA; AES-256; Shamir is unaffected |
| Beneficiary kit stolen | S1 is useless without S2 (after the wait) or S3 |
| Company shuts down | Auto-export + S3 + offline recovery tool |
