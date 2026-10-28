# Security fixes

Findings from the bug bounty (see `../SECURITY.md`) and from our own follow-up
reviews, newest first. Each entry says what was wrong, what an attacker could
do with it, and the commit that fixed it.

## utf8Bytes was not injective -- a lone UTF-16 surrogate encoded identically to U+FFFD (Low)

- **Found:** 2026-10-28, during an internal review of `Hpke.keySchedule`,
  `OwnerToken.compute`, `utf8Bytes` and key-wrap AAD construction, prompted by
  (but independent of) inbound reports naming the same four areas. Those
  reports arrived as PoC zips/PDFs from unverified senders
  (`wantiranti09@gmail.com`, `baiboe7282@gmail.com`) and the attachments were
  not opened, so this finding may or may not be what they describe.
- **What was wrong:** `utf8Bytes` encoded with `dart:convert`'s
  `utf8.encode`, which silently replaces an unpaired UTF-16 surrogate with
  U+FFFD instead of rejecting it. Two different Dart strings -- one holding
  a lone surrogate (reachable via `String.fromCharCodes`), one holding a
  literal U+FFFD at the same position -- therefore encoded to identical
  bytes. Every domain-separation input in this package is built by
  concatenating `utf8Bytes` output: vault id, tier and item/file id in
  `vault.dart`, the vault id in `OwnerToken.compute`, the beneficiary id in
  `SafetyNumber.fingerprint` (the key-substitution defense), and the
  passphrase in `Unlock.deriveUnlockKey`. A non-injective encoder meant two
  distinct ids, or two distinct passphrases, could in principle collide into
  one AAD/MAC/KDF input -- the "confusing two different ... derived inputs
  for one" class the bounty scope calls out. No concrete exploit was
  demonstrated here: every id in the system today is server-issued and
  opaque, and producing a lone surrogate needs `String.fromCharCodes`, not
  normal text entry. The encoder itself was non-injective regardless.
- **Fix:** `utf8Bytes` now throws `SsbCryptoException('invalid string')` on
  an unpaired surrogate instead of silently mangling it, which makes the
  encoding injective for every string it accepts. No behavior change for
  well-formed strings. Regression test: `test/utf8_injective_test.dart`
  (reproduces the `utf8.encode` collision directly, then shows `utf8Bytes`
  refuses one side of it).
- **Open:** the two inbound reports above still need Leon to review the PoC
  attachments in a sandbox before any bounty determination.

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
- **Second follow-up (2026-10-20, reported by Ibnu; same root cause as
  SSB-2026-001):** the note above says every public async function copies its
  caller-owned buffers before its first `await`, but `ItemCrypto.rewrapItemKey`
  still read `item.body` *after* its awaits (it goes into the returned item).
  A delete that wiped the old item's body while a tier-rotation re-wrap was
  pending therefore got a *successful* re-wrap whose body was the wiped bytes:
  a permanently corrupted item that only failed at the next open, as a
  generic decrypt error. `ItemCrypto.open` made the same late read of
  `item.body` but fails closed. Both now copy the body at entry. The earlier
  regression tests covered the `newTierKey` snapshot and post-completion
  aliasing, not this in-flight read. Regression tests:
  `test/rewrap_body_race_test.dart` (the rewrap and open cases both failed
  before the fix). Thank you to Ibnu for the careful follow-up review.
- **App side (not in this repository):** `lock()` no longer wipes keys while
  a vault write is in flight; the write re-checks after every await that its
  keyring is still the live one and aborts without writing otherwise.
