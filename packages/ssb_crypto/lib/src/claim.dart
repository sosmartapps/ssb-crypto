import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// How a beneficiary proves to the server that they are holding the real Kit
/// (spec §6.4).
///
/// The server has no account for them, no password and nothing to remember.
/// What it stores is `sha512(claimToken)`, where the token is itself a hash
/// of the 32-byte X-Wing secret key (seed) printed on their Kit. So:
///
///  * a full database leak yields a hash of a hash of a high-entropy secret,
///    with nothing to brute force;
///  * the server can check a claim without ever being able to make one;
///  * and passing this check still releases nothing on its own -- it only
///    starts the clock. Secrecy rests on the S1/S2 split, not on this.
abstract final class ClaimToken {
  static const _context = 'ssb/v1/claim';

  /// Minimum accepted secret-key length (the X-Wing seed is 32 bytes).
  static const minKeyLength = 32;

  /// The value the beneficiary's device sends.
  ///
  /// Derived from their secret key ALONE -- deliberately not from the vault
  /// id or their beneficiary id. Those are not printed on the Kit, and a
  /// grieving person should be typing one code, not three. The secret key is
  /// 32 uniformly random bytes (256 bits), so it identifies them on its own; the server
  /// finds their record by the hash and hands back the ids it already knows.
  ///
  /// [beneficiarySecretKey] must be at least [minKeyLength] bytes (the real
  /// key is the 32-byte X-Wing seed); an empty or short key would make the
  /// token guessable, so it is refused with [SsbCryptoException]. So is an
  /// all-zero key: that is a wiped buffer, and its token is a constant
  /// (red team 2026-10-20, B6).
  static Future<String> compute({required Uint8List beneficiarySecretKey}) async {
    if (beneficiarySecretKey.length < minKeyLength || isAllZero(beneficiarySecretKey)) {
      throw const SsbCryptoException('bad claim key');
    }
    return hexEncode((await Sha512().hash(concatBytes([
      u16be(2),
      utf8Bytes(_context),
      beneficiarySecretKey,
    ]))).bytes);
  }

  /// What the owner's device uploads, and what the server compares against.
  /// One more hash, so the stored value is never a usable token.
  static Future<String> verifier(String claimToken) async =>
      hexEncode((await Sha512().hash(utf8Bytes(claimToken))).bytes);
}

/// How the OWNER proves to the server that this is their vault (spec §6.4).
///
/// Same shape as [ClaimToken], and for the same reason: no account, no
/// password, nothing to phish or lose. The token is derived from the Vault
/// Key, so it comes back on its own when the vault is restored from an
/// Emergency Kit on a new phone -- which matters more here than anywhere
/// else, because the owner's session is what lets them STOP a release. An
/// identity that could be lost with a phone would be an identity that
/// quietly hands the vault to whoever asks next.
///
/// The server stores sha512 of the token, so it can check an owner without
/// being able to impersonate one, and holds nothing that leads back to the
/// Vault Key.
abstract final class OwnerToken {
  static const _context = 'ssb/v1/owner';

  /// An empty or all-zero [vaultKey] is a disposed keyring, not an owner;
  /// it is refused with [SsbCryptoException] rather than turned into a
  /// constant, guessable token (red team 2026-10-20, B6).
  static Future<String> compute({
    required String vaultId,
    required Uint8List vaultKey,
  }) async {
    if (vaultKey.isEmpty || isAllZero(vaultKey)) {
      throw const SsbCryptoException('bad owner key');
    }
    final v = utf8Bytes(vaultId);
    return hexEncode((await Sha512().hash(concatBytes([
      u16be(1),
      utf8Bytes(_context),
      u16be(v.length),
      v,
      vaultKey,
    ]))).bytes);
  }

  static Future<String> verifier(String ownerToken) async =>
      hexEncode((await Sha512().hash(utf8Bytes(ownerToken))).bytes);
}
