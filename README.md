# ssb_crypto: please try to break it

The cryptographic core of **So Smart Beneficiary**, a zero-knowledge "digital legacy" vault for first responders and military families. An owner seals sensitive information on their own device. Named beneficiaries can open it only after a waiting period the owner can interrupt. The server never holds enough to decrypt anything.

> **Status: NOT independently audited.** This is a request for public review before any real customer data is stored. Do not rely on this code for anything you cannot afford to lose.

**Bounty:** $100 per valid vulnerability. See [SECURITY.md](SECURITY.md) for scope, rules and limits.

## What is in here
| Path | What |
|---|---|
| `packages/ssb_crypto` | The crypto package (about 1,500 lines of Dart): AES-256-GCM envelope encryption with chunked files, HKDF-SHA-384 key hierarchy, Argon2id plus a 128-bit account secret key, HPKE (RFC 9180) with X-Wing (ML-KEM-768 + X25519), hybrid Ed25519 + ML-DSA-65 signatures, Shamir 2-of-3 over GF(256) |
| `third_party/mlkem_native`, `third_party/mldsa_native` | Vendored Dart FFI wrappers around the PQ Code Package C libraries, with our patches (see each `SSB_PATCHES.md`) |
| `docs/CRYPTO-DESIGN.md` | The design: cipher suite, key hierarchy, two-key release, key-substitution defense, threat model |

## Run the tests
Requires Flutter (the native ML-KEM / ML-DSA code is built by a build hook).

```
cd packages/ssb_crypto
flutter pub get
flutter test
```

## Where to look first
- The release flow and key-substitution defense: `lib/src/release.dart`, `claim.dart`, `safety_number.dart`
- The vendored native wrappers and our patches: `third_party/*/SSB_PATCHES.md`
- Anything where two inputs could be confused for one another (domain separation, encodings)

## Known limitations (so you do not spend time on them)
- The crypto is pure Dart today. It is not constant-time and secrets cannot be reliably wiped from memory. Native and hardware-backed primitives are planned.
- Removing a beneficiary does not yet rotate the tier keys.
- The server (Firebase) code is not part of this repository.

## Contact
leon@sosmartapps.app. License: MIT (see LICENSE).
