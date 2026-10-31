# Security fixes

Findings from the bug bounty (see `../SECURITY.md`) and from our own follow-up
reviews, newest first. Each entry says what was wrong, what an attacker could
do with it, and the change that fixed it.

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

- **2026-10-31, hel (Low, hardening): "padmeLength() leaks exact plaintext length" and "openWithPassphrase() runs Argon2id twice on non-key failures."**
  The first is not a vulnerability: Padmé is implemented as specified, and
  lengths already on a bucket boundary map to their own bucket, so an observer
  learns only the bucket, never the exact length. The second was real but is a
  cost/DoS inefficiency, which SECURITY.md lists as out of scope, so it does not
  qualify for a reward. We fixed it anyway: a failure after the key has
  verified (`SsbPostUnlockException`) no longer triggers the legacy-form retry,
  and Argon2id parameters read from a manifest now have a ceiling. Thank you to
  hel for the report; credited as a participant. (No advisory number: this is
  not a vulnerability.)

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

## 2026-10-27 — follow-up reports (Ari)

Two further reports (credited to Ari) found the same root cause as SSB-2026-001, a caller-owned buffer read after an `await`, in two functions our earlier sweeps had not covered. Neither exposes vault data; both could return a wrong value silently if the caller wiped or overwrote its buffer while the call was pending.

- **`Hpke.keySchedule` read `info` and `sharedSecret` after an `await`.** The key schedule is built from several awaited steps; `info` was read at the second and `sharedSecret` at the third, so a buffer changed after the call had returned its `Future` produced a different key schedule with no error. *Fix:* both buffers are copied before the first `await` and the copies are wiped afterwards. Tests: `test/redteam_ari_keyschedule_safety_test.dart`, four cases that failed before the fix.
- **`SafetyNumber.fingerprint` read `publicKey` after an `await`.** The key is mixed into each of the 5200 rounds, so a buffer changed mid-computation gave a different safety number with no error. *Fix:* the key is copied before the first `await`. Tests: three cases in `test/redteam_ari_keyschedule_safety_test.dart`, two of which failed before the fix.
- **Already fixed:** the third item in the report, the recipient key read by `XWing.encapsulateDerand`, was fixed in the 2026-10-26 sweep as RT-2 (below).

Because two functions had been missed, we replaced the manual sweep with a mechanical one. `test/redteam_snapshot_harness_test.dart` calls every public `Future`-returning function that takes a buffer (56 of them), wipes or bit-flips every argument right after the call returns, and requires the result to equal the one from pristine arguments. A registry in the same file fails the build if a new such function is added without a case. The harness found the same pattern in further places, all fixed the same way (copy before the first `await`): the `nonce` argument of `Aead.seal`; the blob arguments of `Aead.open`, `Aead.openLegacyV1`, `StreamCipher.decrypt`, `StreamCipher.decryptLegacyV1` and `Hpke.open`; the data argument of `StreamCipher.encrypt`; the ciphertext of `XWing.decapsulate`; `HybridSignature.verify` and `OwnerIdentity.verifyChallenge`; the legacy-form retry in `Unlock.openWithPassphrase`; `Release.recoverWithServerShare` and `ReleaseV1.recoverWithServerShare`; the key-check comparison in `Shamir.combine` and `ShamirV1.combine`; `VaultKeyring.open` and `VaultKeyring.fromVaultKey` (manifest blob, wrapped vault key, tier map, item list); `ItemCrypto.openFile`; and the v1 read paths `VaultKeyringV1`, `ItemCryptoV1.open` and `ItemCryptoV1.openFile`. In most of these the effect was a spurious "decrypt failed" or "stale slot" rather than a wrong value; none lets an outsider read or forge data.

## 2026-10-26 — our own red-team follow-up (sweep for siblings of SSB-2026-001 to -004)

After four external reports in six days we read every context builder and every public entry point of `packages/ssb_crypto` for the shapes those reports had, and wrote a failing test for each candidate. Three real issues were found and fixed; none lets an outsider read, forge or roll back vault data.

- **RT-1, tier export chain could fork (Low-Medium; found by us).** Two overlapping `sealTierExport` calls for the same tier both read the same sequence number and previous-export hash before either finished, so the keyring's recorded chain head could name an export the server had rejected, and a beneficiary's chain check would then fail until the next rotation. No attacker was needed: the app could trigger it with two quick edits. *Fix:* the key, epoch and plaintext are snapshotted before the first `await` and calls for one tier run strictly one after another. Tests: `test/redteam_siblings_test.dart`.
- **RT-2, recipient public key read after an `await` (Low; same pattern as SSB-2026-001).** SSB-2026-001 covered secret buffers; `XWing.encapsulateDerand` and `Release.create` also validated the caller's *public* key buffer and then read it again after awaiting. A buffer wiped or overwritten in that window of about a millisecond could make the post-quantum half of the hybrid seal to a zero key, leaving only the X25519 half protecting the share. It needed a wipe of the recipient-key buffer at exactly that moment. *Fix:* the public key and the encapsulation seed are copied before the first `await`, validated as copies, and the seed copy is wiped afterwards. Tests: three cases in `test/redteam_siblings_test.dart`, each failing before the fix.
- **RT-3, integer encoders truncated silently (Low, hardening; same family as SSB-2026-004).** `u16be`/`u32be` reduced out-of-range values (an epoch of 2^32 encoded like 0, a 65,536-byte id like a 0-byte one), so "no two inputs encode alike" held only for in-range input. Epochs come from the keyring or from authenticated headers, so no attack was found, but a test showed an item sealed at epoch 0 opening at epoch 2^32. *Fix:* both encoders now throw outside 0..0xffff and 0..0xffffffff. Tests: `test/redteam_siblings_test.dart`, `test/redteam_ssb2026_004_regression_test.dart`.
- **Pinned, not changed.** The v1 read-only code keeps its old `|`-joined contexts because it must reproduce what was sealed earlier; tests prove the collision is still present in those encodings and that no caller can reach it (`test/redteam_injectivity_test.dart`). The same file registers every `ctx2` label and fails the build if a new context builder is added without an injectivity test.

## SSB-2026-004 — key-wrap context collision across vault, tier and item ids (Low)

- **Reported:** 2026-10-25 by Lehem Costa, against `a7f304f`. First report of this root cause. Thank you, Lehem.
- **What was wrong:** in format v1 the data a wrapped item or file key was bound to was the string `ssb/v1/ik|vault:<vaultId>|tier:<tier>|item:<itemId>` with no length prefixes. Two different tuples, for example vault `V|tier:ice|item:B` with item `C`, and vault `V` with item `B|tier:ice|item:C`, produced identical bytes, so a wrapped key opened in the other slot. The sibling Vault Key slot context (`ssb/v1/vk/<slot>|vault:<vaultId>`) had the same shape.
- **What an attacker could do:** the item *body* context did not include the tier, so no plaintext was exposed, and the attack needs an identifier containing the literal delimiter text, which the app does not generate. It still broke the binding between a key and the slot it belongs to, which is a domain-separation flaw.
- **Fix:** format v2 builds every context with `ctx2`: `'ssb/v2/'` plus length-prefixed fields and fixed-width integers, with the key generation bound in. The collision cannot occur in v2. Format-v1 objects are open-only through `legacy_v1.dart` (migration), and are reachable only with keys already authenticated by their own vault. Regression tests: `test/redteam_ssb2026_004_regression_test.dart` seals under the first tuple and requires the second to be refused by key unwrap, `ItemCrypto.open`, `rewrapItemKey`, and `sealFile`/`openFile`, in both directions, for all nine tier pairs, plus the slot and tier-export variants and the epoch dimension.

## SSB-2026-003 — vault ids were not bound to a key (crypto part)

- **Reported:** 2026-10-20 audit follow-up, credited to Ibnu for the review that led to it.
- **What was wrong:** a vault id was an arbitrary string. The first sign-in for an id the server had not seen registered it, bound to whatever token arrived, and the server could not check that token because it is a hash of a key the server never sees (trust on first use). Whoever registered an id first owned it.
- **What an attacker could do:** register ("squat") a vault id they expected someone else to use, so that the real owner's sign-in or deletion was refused or attributed to the attacker. This is an identity and availability problem for the service; it does not reveal vault contents, which stay encrypted under keys the server never holds.
- **Fix (the part in this repository):** `OwnerIdentity` derives an Ed25519 key deterministically from the Vault Key, and a self-certifying vault id is `v2_` plus 40 hex characters of `SHA-256('ssb/v2/vault-id' || publicKey)`. A server can verify a signature over a fresh challenge and that the id is the hash of the key it was given, so an id cannot be claimed without the key. Known-answer vector: `test/vectors/owner_identity_kat.json`; tests: `test/owner_identity_test.dart`. The challenge-and-verify endpoints are server code and are not part of this repository.

## SSB-2026-002 — tier keys, slots, items and manifests could be rolled back (Medium)

- **Reported:** 2026-10-20 by Ibnu (with proofs of concept for seven replay and rollback cases), against format v1.
- **What was wrong:** nothing in a v1 object said which *generation* of the vault it belonged to. A server (or a restored backup) could hand back an older wrapped tier key, an older passphrase slot, an older copy of an edited item, an older beneficiary export, or an older Beneficiary Kit share pair, and each opened cleanly.
- **What an attacker could do:** after the owner rotated a tier key, revoked a beneficiary, changed a passphrase, edited or deleted an item, a malicious or compromised server could silently put the vault back into the earlier state. In particular it could re-admit a revoked key or beneficiary and present stale data as current. It could not decrypt anything it could not decrypt before.
- **Fix:** format v2. Per-tier epochs and per-slot epochs are bound into every wrap context; a sealed manifest under the Vault Key records the current epochs, slot hashes, item-set hash, beneficiary-set hash and tier-export heads; a monotonic `seq` in the manifest is checked against a per-device anchor; tier exports carry `(epoch, seq, prevHash)`; Beneficiary Kits and the server share carry the epoch, so a pre-rotation Kit fails with "kit from an older key generation". Design: `CRYPTO-DESIGN.md` section 2a. Regression tests (each attack ran green against v1 and must fail against v2): `test/freshness_regression_test.dart`, `old_manifest_refused_test.dart`, `old_slot_refused_test.dart`, `cross_epoch_shares_test.dart`, `v1_v2_confusion_test.dart`, `manifest_items_hash_test.dart`, `tier_export_v2_test.dart`, `kit_v2_length_test.dart`.
- **Residuals we document rather than hide:** the web anchor lives in `localStorage`, which can be cleared; a device that has never seen the vault cannot detect a same-epoch rollback until an owner-signed manifest head exists; files are not yet in the manifest (the app stores none today).

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
