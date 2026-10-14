# So Smart Beneficiary: cryptographic design

Extract of the crypto sections of the product spec. Business, pricing and operations sections are omitted. Status: **not independently audited.** Where the text describes hardware-backed or native primitives, that is the roadmap; the code today is pure Dart (see the package README).


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
| Key hierarchy | Vault Key → Tier Keys (T0/T1/T2) → per-item keys, each wrapped with AES-256-GCM; derivations via **HKDF-SHA-384** | Compromise of one item key exposes one item; tiers map to release rules |
| Owner passphrase | **Argon2id** (RFC 9106), calibrated per device (target ≥ 128 MiB memory, ~0.5–1 s) | Memory-hard; the current OWASP first choice against GPU cracking |
| Second secret | **128-bit Account Secret Key**, generated on device, mixed with the passphrase via HKDF, printed in the Emergency Kit | A stolen server database can't be brute-forced even with a weak passphrase (same model as 1Password) |
| Sharing with beneficiaries | **HPKE (RFC 9180) with X-Wing KEM = ML-KEM-768 + X25519** | Hybrid post-quantum; native in Apple CryptoKit (iOS 26+) |
| Signatures (enrollment, release tokens, audit log) | **Ed25519 + ML-DSA-65** (hybrid, both must verify) | Server-issued release tokens and audit entries can't be forged, now or post-quantum |
| Beneficiary release split | **Shamir 2-of-3 over GF(256)**, each share with an integrity tag (so secrets must be uniformly random, >= 16 bytes: one share lets an attacker confirm a guess of a low-entropy secret) | Security doesn't depend on computing power, so quantum computers don't affect it |
| App login | **Passkeys** (WebAuthn/FIDO2) for owners and beneficiaries; the vault passphrase never leaves the device | Phishing-resistant; account login and vault decryption are separate |
| Transport | TLS 1.3, hybrid PQ key exchange (X25519MLKEM768) where supported | Defense in depth only; security never depends on it |

**Implementation status today (read this before relying on the table above).** The AES-256-GCM, HKDF, Argon2id, X25519, Ed25519 and SHA-2 code in `packages/ssb_crypto` is **pure Dart** (`cryptography` 2.9.0 in its Dart backend; no `cryptography_flutter`, no libsodium, no CryptoKit). It is correct and covered by test vectors, but it is **not hardware-accelerated and not guaranteed constant-time**: Dart's AES and GHASH are table/branch based and can leak through timing and cache side channels to an attacker who can run code on the same device. Only ML-KEM and ML-DSA run as native C (the vendored PQ Code Package wrappers in `third_party/`). Secrets cannot be reliably wiped from Dart memory: the code zeroes buffers it owns on a best-effort basis (`wipe()`), but Dart's garbage collector may already have copied them. *Roadmap:* move AES-GCM, HKDF, Argon2id, X25519 and Ed25519 to native or platform primitives (CryptoKit, libsodium, platform crypto, per §6.4), keep secrets in native memory, and use Secure Enclave / StrongBox; this is a pre-launch item tracked with the independent audit in §6.5.

**Passphrase normalization.** The passphrase is Unicode **NFKD**-normalized before Argon2id (`Unlock.normalizePassphrase`), so the same passphrase typed on different keyboards/IMEs (precomposed vs combining accents, full-width Latin, ligatures, no-break spaces) derives the same Unlock Key. ASCII is unaffected, so ASCII passphrases derive the same keys as before. Vaults sealed before normalization shipped (2026-09) open through `Unlock.openWithPassphrase`, which tries the normalized key first and, only when NFKD changes the passphrase, retries once with the raw form. The unlock slot is not re-wrapped automatically; any future passphrase-change or re-wrap flow must seal with `Unlock.deriveUnlockKey` (normalized). Normalization tables come from `unorm_dart` 0.3.2 (pinned) — NFKD is stable for assigned code points under Unicode's normalization stability policy, so upgrading the table cannot change keys for characters it already covers.

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
