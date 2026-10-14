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
    params.validateForUnlock();
    final pw = utf8Bytes(normalize ? normalizePassphrase(passphrase) : passphrase);
    final a = await argon2id(pw, accountSalt, params);
    final b = await hkdfSha384(ikm: secretKey, salt: accountSalt, info: 'ssb/v1/secret-key');
    final muk = await hkdfSha384(
        ikm: concatBytes([a, b]), salt: accountSalt, info: 'ssb/v1/unlock-key');
    wipe(pw);
    wipe(a);
    wipe(b);
    return muk;
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
    final muk = await deriveUnlockKey(
        passphrase: passphrase, secretKey: secretKey,
        accountSalt: accountSalt, params: params);
    try {
      return await open(muk);
    } on SsbCryptoException {
      if (!hasLegacyForm(passphrase)) rethrow;
    } finally {
      wipe(muk);
    }
    final legacy = await deriveUnlockKey(
        passphrase: passphrase, secretKey: secretKey,
        accountSalt: accountSalt, params: params, normalize: false);
    try {
      return await open(legacy);
    } finally {
      wipe(legacy);
    }
  }
}
