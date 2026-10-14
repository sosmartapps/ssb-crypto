# Vendored: mlkem_native 1.0.4 (MIT) wrapping PQ Code Package mlkem-native

Source: https://pub.dev/packages/mlkem_native (rkz-app/mlkem_native_port),
vendored on 2026-09-11 so every line of native crypto we ship is reviewed and pinned.
Trimmed to the files the build hook compiles (proofs/tests/nix removed; licenses kept).

## Patches applied by So Smart Beneficiary

1. **Keygen coin size (security bug).** `generateKeyPair(coins:)` validated
   32 bytes, but `crypto_kem_keypair_derand` reads `2*MLKEM_SYMBYTES` = 64
   bytes (FIPS 203 d||z). The upstream wrapper over-read 32 bytes of heap.
   Now requires exactly 64 bytes.
2. **RNG fallback (security bug).** Linux/Android `randombytes()` ignored
   `read()`'s return value (short or failed reads left buffers unfilled) and
   Apple/Windows return codes were passed through unnormalized. Rewritten to
   loop, handle EINTR, and fail closed. SSB never relies on it anyway: all
   calls go through the `*_derand` entry points with coins from
   `Random.secure()`.
3. **Zeroization.** Native buffers that held secret keys, shared secrets or
   coins are wiped before `calloc.free`.
4. **Length validation audit.** Every entry point already checked key, ciphertext and coin
   lengths against the exact sizes C reads (no over-read, unlike the ML-DSA wrapper, see
   `../mldsa_native/SSB_PATCHES.md` patch 3). The coin checks ran after native buffers were
   allocated, so a wrong-size `coins` leaked them; all checks now run first.
   Regression tests: `packages/ssb_crypto/test/regression_mlkem_ffi_lengths_test.dart`.

Correctness is gated by the X-Wing test vectors in
`packages/ssb_crypto/test/xwing_test.dart`, which exercise ML-KEM-768
derandomized keygen, encapsulation and decapsulation end-to-end.
Report upstream after our audit.
