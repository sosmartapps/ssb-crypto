# ssb_crypto

Zero-knowledge, hybrid post-quantum crypto core for So Smart Beneficiary.
Design: `docs/SPEC.md` §6. Suite v1:

| Job | Algorithm | Verified by |
|---|---|---|
| Hybrid KEM | X-Wing (ML-KEM-768 + X25519) | draft-connolly-cfrg-xwing-kem-10 Appendix C vectors (all 3) |
| Public-key encryption | HPKE RFC 9180 base mode, X-Wing / HKDF-SHA256 / AES-256-GCM | RFC 9180 key-schedule + encryption vector |
| Data | AES-256-GCM, per-item keys, versioned header bound in AAD | tamper/downgrade/type-confusion tests |
| Files | STREAM (64 KiB chunks) | truncation/extension/reorder tests |
| KDF | HKDF-SHA-384 | independent Python computation |
| Passphrase | Argon2id (128 MiB, t=3) + 128-bit Secret Key | RFC 9106 §5.3 vector |
| Release split | Shamir 2-of-3, GF(2^8), constant-time field ops; secrets must be uniformly random, >= 16 bytes | recover/insufficient/mismatch tests |
| Key verification | Safety numbers (5200× SHA-512) | determinism/sensitivity tests |

Also implemented: ML-DSA-65 + Ed25519 hybrid signatures (`signature.dart`) and Unicode NFKD passphrase
normalization (`unlock.dart`).

**What this package is and is not (current truth).** Everything except ML-KEM and ML-DSA is pure Dart
(`cryptography` 2.9.0 Dart backend, no `cryptography_flutter`, no libsodium): AES-256-GCM, HKDF, Argon2id,
X25519, Ed25519 and SHA-2 are correct and vector-tested but NOT hardware-accelerated and NOT guaranteed
constant-time (Dart AES/GHASH are table/branch based). ML-KEM-768 and ML-DSA-65 are native C via the
vendored PQ Code Package wrappers in `third_party/`. Wiping secrets from memory is best-effort only: `wipe()`
zeroes the buffers this code owns, but Dart's GC may have copied them first. Not built yet (roadmap, see
`docs/SPEC.md` §6.2/§6.4): native or platform AES/Argon2/X25519/Ed25519, native secret storage, and
Secure Enclave / StrongBox key storage.

Run: `dart test` (needs a C toolchain; the ML-KEM native code builds automatically).
Vendored native wrappers and the security fixes applied: `third_party/mlkem_native/SSB_PATCHES.md`,
`third_party/mldsa_native/SSB_PATCHES.md`.

Shamir note: the polynomial shares are information-theoretic, but each share also carries an 8-byte
HKDF tag of the secret (to detect mismatched/corrupt shares). One share therefore lets an attacker
confirm a guess of a LOW-ENTROPY secret, so `Shamir.split` only accepts secrets of at least 16 bytes
and callers must pass uniformly random keys (the tier keys are 256-bit random).

Domain labels: signatures (`ssb/v2/sig`) and the S2 HPKE info (`ssb/v2/s2`) use length-prefixed
fields (v1 used `|` delimiters, which were ambiguous). Format break from v1 is intentional.
The AEAD contexts in `lib/src/vault.dart` (`ssb/v1/...|vault:...|item:...`) still use `|`. That is safe
there: each context is paired with a different key (item key wrapped under the tier key, body under the
item key), so the (key, AAD) pair is injective even if an id contained `|`. Do not copy that pattern to
anywhere a single key covers several delimited contexts; use length-prefixed fields.
