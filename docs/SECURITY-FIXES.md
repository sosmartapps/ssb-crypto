# Security fixes

Findings from the bug bounty (see `../SECURITY.md`) and from our own follow-up
reviews, newest first. Each entry says what was wrong, what an attacker could
do with it, and the commit that fixed it.

## Reports reviewed and not accepted

- **2026-10-19, Ibnu (Low): "Hpke.keySchedule omits psk_id_hash from the secret."**
  Not a vulnerability and not a deviation. RFC 9180 section 5.1 puts
  `psk_id_hash` in the key-schedule *context*; the *secret* is
  `LabeledExtract(shared_secret, "secret", psk)` and `psk` is the empty string
  in base mode, so an empty IKM is correct. We reproduced the official RFC 9180
  Appendix A.1.1 vector independently: our construction gives the RFC's
  `base_nonce` and `exporter_secret` exactly, while the proposed change does
  not. The official vector is now a regression test
  (`test/hpke_rfc_official_test.dart`). Thank you to Ibnu for the careful
  review; credited as a participant.

## SSB-2026-001 — in-flight wrap sealed a zero key when the keyring was rotated or disposed (Medium)

- **Reported:** 2026-10-15 by ATOSAN (first report under
  the bounty). Tested against `69740b2`.
- **What was wrong:** `VaultKeyring.wrapTierKey()` handed the live tier-key
  buffer to `Aead.seal()`, which awaited before AES-GCM read it. A
  `rotateTier()` or `dispose()` that ran in that window wiped the buffer
  first, so the stored wrapped tier key silently became 32 zero bytes with no
  error anywhere. Items sealed afterwards were encrypted under a public key.
  `wrapVaultKey()` + `dispose()` had the same bug.
- **Follow-up review (same day):** the same pattern existed in
  `ItemCrypto.rewrapItemKey` (newTierKey read after the unwrap await — a
  lock during a beneficiary removal re-wrapped every item key under zeros and
  the app pushed the result to the server), `ItemCrypto.seal/sealFile`
  (plaintext), `Shamir.split` and `Release.create` (secret — a wipe produced
  shares and a key-check that consistently "recovered" an all-zero tier key,
  i.e. a silently dead Beneficiary Kit), `hkdfSha384` (ikm is read lazily by
  package:cryptography), `Unlock.deriveUnlockKey` (Secret Key read after the
  Argon2 await — a wipe turned it into a passphrase-only key), `Hpke.seal`
  (plaintext/info), `KitCode.encode` (payload), `XWing.generateKeyPairDerand`
  (seed), and `StreamCipher` (file key).
- **Fix:** every public async function now copies each caller-owned secret
  (and any caller-owned AAD/info) before its first `await` and wipes the copy
  when done. Three tripwires make a repeat loud instead of silent:
  `Aead` and `StreamCipher` reject an all-zero key; `VaultKeyring.dispose()`
  marks the keyring dead and every key-using method throws afterwards
  (`tierKey()` is the checked accessor); `VaultKeyring.open/fromVaultKey`
  wipe what they unwrapped if a later wrap is rejected. `rewrapItemKey` no
  longer returns a body that aliases the input. Regression tests:
  `test/wipe_race_test.dart` (21 cases, each failing before the fix).
- **Hardening notes from the same report (also fixed):** `VaultKeyring.open`
  exception path, second copy of the Ed25519 seed in
  `HybridSignature.generateKeyPair`, Shamir shares in `Release.*`, HPKE
  `exporterSecret`, the unlock-key pre-image in `Unlock.deriveUnlockKey`, and
  `rewrapItemKey` body aliasing — all now wiped / copied.
- **App side (not in this repository):** `lock()` no longer wipes keys while
  a vault write is in flight; the write re-checks after every await that its
  keyring is still the live one and aborts without writing otherwise.
