# Vendored: mldsa_native 1.0.0 (MIT) wrapping PQ Code Package mldsa-native

Source: https://pub.dev/packages/mldsa_native (rkz-app/mldsa_native_port), vendored 2026-09-11.
Trimmed to what the build hook compiles; licenses kept.

## Patches applied by So Smart Beneficiary
1. **RNG fallback.** Linux/Android `randombytes()` ignored `read()`'s return value and the
   Apple/Windows return codes were unnormalized — same flaw as the ML-KEM wrapper. Replaced with
   the hardened version (loops, handles EINTR, fails closed). SSB passes its own coins from
   `Random.secure()` for keygen anyway.
2. **Zeroization.** Secret-key buffers are wiped before `calloc.free`.
3. **Length validation (memory safety).** Upstream sized native buffers from the caller's
   arrays but told C a fixed size. `sign` allocated `privateKey.length` bytes, C read
   `secretKeyBytes` (4032 for ML-DSA-65) and patch 2 then wrote `secretKeyBytes` zeros back:
   a heap over-read and, on the wipe, a heap overflow for a short key. `verify` likewise
   over-read a short `publicKey`. Now, before any native allocation: `sign` requires exactly
   `secretKeyBytes` for the private key (the buffer is allocated at that size), `verify`
   requires exactly `publicKeyBytes` (both throw the new `MLDSAWrongLengthException`, an
   `MLDSAException`), a wrong-size signature makes `verify` return `false` without calling C,
   `coins` must be 32 bytes in every entry point that accepts them (`generateKeyPair`, `sign`;
   keygen coins are now checked before allocating, and wiped after use), and contexts over 255
   bytes (FIPS 204) are refused. Regression tests:
   `packages/ssb_crypto/test/regression_mldsa_ffi_sign_test.dart`, `..._verify_test.dart`.

Keygen coins are 32 bytes here, which matches FIPS 204 (xi) — unlike the ML-KEM wrapper, no
size bug to fix.

Correctness is gated by cross-implementation tests in
`packages/ssb_crypto/test/signature_test.dart`: keys, signatures and verification must agree
with the independent pure-Dart `pqcrypto` implementation (which ships NIST vector evidence).
