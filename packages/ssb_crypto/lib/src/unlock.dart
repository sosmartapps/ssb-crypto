import 'dart:typed_data';

import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'bytes.dart';
import 'kdf.dart';
import 'kit_code.dart';

/// Two-secret key derivation (spec §6.2): the passphrase is stretched with
/// Argon2id and combined with a 128-bit Account Secret Key that never
/// leaves the owner's devices or printed Emergency Kit. A stolen server
/// database is therefore useless for offline guessing, even against a weak
/// passphrase.
///
/// The passphrase and the Secret Key are never sent to the server.
abstract final class Unlock {
  static const secretKeyLength = 16;
  static const saltLength = 16;
  static const secretKeyLabel = 'SSB1-SK';

  static Uint8List newSecretKey() => randomBytes(secretKeyLength);
  static Uint8List newAccountSalt() => randomBytes(saltLength);

  static Future<String> formatSecretKey(Uint8List sk) =>
      KitCode.encode(secretKeyLabel, sk);
  static Future<Uint8List> parseSecretKey(String code) =>
      KitCode.decode(secretKeyLabel, code, payloadLength: secretKeyLength);

  /// Unicode NFKD form of [passphrase] — the form that is actually stretched.
  ///
  /// The same passphrase can arrive as different code points depending on
  /// the keyboard/IME/OS: "é" precomposed (U+00E9) vs "e" + combining acute
  /// (U+0065 U+0301), full-width Latin from CJK keyboards, ligatures such as
  /// "ﬁ", non-breaking vs regular spaces. NFKD maps each of these to one
  /// canonical sequence so they all derive the same key. ASCII is unchanged,
  /// so ASCII passphrases derive exactly the keys they always did.
  static String normalizePassphrase(String passphrase) =>
      unorm.nfkd(passphrase);

  /// True when [passphrase] changes under NFKD — i.e. a vault sealed before
  /// normalization shipped may have been wrapped with the raw form, and
  /// [openWithPassphrase] will fall back to it.
  static bool hasLegacyForm(String passphrase) =>
      normalizePassphrase(passphrase) != passphrase;

  /// Derives the 32-byte Unlock Key that wraps the Vault Key.
  ///
  /// The passphrase is NFKD-normalized ([normalizePassphrase]) before
  /// Argon2id. Use this when SEALING (creating a vault or re-wrapping the
  /// unlock slot). When OPENING an existing vault use [openWithPassphrase],
  /// which also accepts vaults sealed before normalization.
  ///
  /// [normalize] = false reproduces the pre-normalization derivation and
  /// exists only for that backward-compatible open path and its tests.
  static Future<Uint8List> deriveUnlockKey({
    required String passphrase,
    required Uint8List secretKey,
    required Uint8List accountSalt,
    required Argon2Params params,
    bool normalize = true,
  }) async {
    if (secretKey.length != secretKeyLength || accountSalt.length != saltLength) {
      throw const SsbCryptoException('bad unlock input');
    }
    // Tripwires (red team 2026-10-20, B6). An all-zero Secret Key is a wiped
    // buffer, and deriving from it would quietly turn this into a
    // passphrase-only key -- the exact failure the Secret Key exists to
    // prevent. A zero salt is never generated either, and an empty
    // passphrase would rest on the Secret Key alone. (The app enforces its
    // own passphrase policy on top of this.)
    if (isAllZero(secretKey) || isAllZero(accountSalt) || passphrase.isEmpty) {
      throw const SsbCryptoException('bad unlock input');
    }
    params.validateForUnlock();
    final pw = utf8Bytes(normalize ? normalizePassphrase(passphrase) : passphrase);
    // Snapshot the Secret Key and salt before the (long) Argon2 await, so a
    // caller wiping the Secret Key mid-derivation cannot silently turn this
    // into a passphrase-only key (see Aead.seal).
    final sk = Uint8List.fromList(secretKey);
    final salt = Uint8List.fromList(accountSalt);
    Uint8List? a, b, ikm;
    try {
      // The cheap half first, so the Secret Key is consumed before the
      // slow Argon2 step even starts.
      b = await hkdfSha384(ikm: sk, salt: salt, info: 'ssb/v1/secret-key');
      a = await argon2id(pw, salt, params);
      // The concatenation is the full unlock-key pre-image; it gets the
      // same wipe as its halves, on every exit path.
      ikm = concatBytes([a, b]);
      return await hkdfSha384(ikm: ikm, salt: salt, info: 'ssb/v1/unlock-key');
    } finally {
      wipe(pw);
      wipe(sk);
      wipe(a);
      wipe(b);
      wipe(ikm);
    }
  }

  /// Opens an existing vault: derives the (normalized) Unlock Key and hands
  /// it to [open] — e.g. `(k) => VaultKeyring.open(kek: k, ...)`.
  ///
  /// Backward compatibility: vaults sealed before NFKD normalization were
  /// wrapped with a key derived from the raw passphrase. If [open] rejects
  /// the normalized key with [SsbCryptoException] AND the passphrase has a
  /// different raw form ([hasLegacyForm]), the legacy raw derivation is
  /// tried once. ASCII / already-normalized passphrases never pay for a
  /// second Argon2id. Each derived key is wiped after [open] returns, so
  /// [open] must not keep a reference to it.
  static Future<T> openWithPassphrase<T>({
    required String passphrase,
    required Uint8List secretKey,
    required Uint8List accountSalt,
    required Argon2Params params,
    required Future<T> Function(Uint8List unlockKey) open,
  }) async {
    // Snapshot the Secret Key and salt before the first await (see
    // Aead.seal): the legacy-form retry below derives from them a second
    // time, after the first derivation and the caller's open() callback have
    // yielded, and it must see the same bytes the first attempt saw.
    final sk = Uint8List.fromList(secretKey);
    final salt = Uint8List.fromList(accountSalt);
    try {
      final muk = await deriveUnlockKey(
          passphrase: passphrase, secretKey: sk,
          accountSalt: salt, params: params);
      try {
        return await open(muk);
      } on SsbCryptoException {
        if (!hasLegacyForm(passphrase)) rethrow;
      } finally {
        wipe(muk);
      }
      final legacy = await deriveUnlockKey(
          passphrase: passphrase, secretKey: sk,
          accountSalt: salt, params: params, normalize: false);
      try {
        return await open(legacy);
      } finally {
        wipe(legacy);
      }
    } finally {
      wipe(sk);
      wipe(salt);
    }
  }
}
