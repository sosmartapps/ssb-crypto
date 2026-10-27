import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';
import 'kdf.dart';

/// The owner's self-certifying identity (docs/CRYPTO-DESIGN.md, SSB-2026-003).
///
/// WHY. The first sign-in for an unknown vault id used to REGISTER it, bound
/// to whatever token arrived (trust on first use). The server cannot check
/// such a token -- it is a hash of a key the server has never seen -- so
/// whoever registered an id first owned it. Hashing the Vault Key into the id
/// does not help on its own; what closes the gap is that the server can
/// check a SIGNATURE.
///
/// HOW.
///
///   seed      = HKDF-SHA-384(ikm = Vault Key, salt = "", info = "ssb/v2/owner-sign", 32)
///   keypair   = Ed25519 from seed          (deterministic: same Vault Key, same identity)
///   vaultId   = "v2_" || hex(SHA-256("ssb/v2/vault-id" || publicKey)[0..20])
///
/// The id is a hash of the public key, so it is bound to the key by
/// construction: nobody can register an id they do not hold the key for, and
/// an id cannot be "guessed" into someone else's ownership. Sign-in is a
/// challenge-response: the server issues a nonce, the client signs
///
///   purpose || lp(vaultId) || u16be(len(nonce)) || nonce
///
/// (`lp` = [lengthPrefixed], a 4-byte length), and the server checks the
/// signature AND that the id is the hash of the key it was given.
///
/// Ed25519 only for now: the server verifies it with `node:crypto`. The
/// ML-DSA-65 leg joins when the server gets a verifier for it (docs/CRYPTO-DESIGN.md);
/// the id derivation would then include that key and ship as `v3_`.
///
/// A vault whose id does not start with `v2_` is a format-v1 vault (random
/// id) and signs in with the legacy `OwnerToken`; the server accepts that
/// only for vaults it already holds.
class OwnerIdentity {
  OwnerIdentity._(this.publicKey, this.vaultId);

  /// Ed25519 public key (32 bytes).
  final Uint8List publicKey;

  /// `v2_` + 40 hex characters; derived from [publicKey].
  final String vaultId;

  static const idPrefix = 'v2_';
  static const idContext = 'ssb/v2/vault-id';
  static const seedInfo = 'ssb/v2/owner-sign';

  /// Signing purposes. Each is a different domain, so a signature made for
  /// one (sign-in) cannot be replayed for another (vault deletion).
  static const authPurpose = 'ssb/v2/owner-auth';
  static const deletePurpose = 'ssb/v2/owner-delete';

  static const nonceMin = 16, nonceMax = 64;

  static final _ed = Ed25519();

  /// True for an id in the self-certifying format.
  static bool isSelfCertifyingId(String vaultId) => vaultId.startsWith(idPrefix);

  /// The identity belonging to [vaultKey]. Deterministic. [vaultKey] is read
  /// before the first await (SSB-2026-001) and the derived seed is wiped.
  static Future<OwnerIdentity> derive(Uint8List vaultKey) async {
    final seed = await _seed(vaultKey);
    try {
      final kp = await _ed.newKeyPairFromSeed(Uint8List.fromList(seed));
      final pk = Uint8List.fromList((await kp.extractPublicKey()).bytes);
      return OwnerIdentity._(pk, vaultIdFor(pk));
    } finally {
      wipe(seed);
    }
  }

  /// The vault id for an owner [publicKey].
  static String vaultIdFor(Uint8List publicKey) {
    if (publicKey.length != 32) throw const SsbCryptoException('bad owner key');
    final h = sha256Of(concatBytes([utf8Bytes(idContext), publicKey]));
    return '$idPrefix${hexEncode(h.sublist(0, 20))}';
  }

  /// The exact bytes that are signed (and that the server rebuilds).
  static Uint8List challengeMessage(String vaultId, Uint8List nonce,
      {String purpose = authPurpose}) {
    _checkNonce(nonce);
    return concatBytes([
      utf8Bytes(purpose),
      lengthPrefixed(vaultId),
      u16be(nonce.length),
      nonce,
    ]);
  }

  /// Signs the server's [nonce] as the owner of [vaultId]. Throws
  /// [SsbCryptoException] if [vaultId] is not the id [vaultKey] derives to:
  /// a legacy (v1) vault must not even try this path.
  static Future<Uint8List> signChallenge({
    required Uint8List vaultKey,
    required String vaultId,
    required Uint8List nonce,
    String purpose = authPurpose,
  }) async {
    final message = challengeMessage(vaultId, nonce, purpose: purpose);
    final seed = await _seed(vaultKey);
    try {
      final kp = await _ed.newKeyPairFromSeed(Uint8List.fromList(seed));
      final pk = Uint8List.fromList((await kp.extractPublicKey()).bytes);
      if (vaultIdFor(pk) != vaultId) {
        throw const SsbCryptoException('vault id does not match key');
      }
      return Uint8List.fromList((await _ed.sign(message, keyPair: kp)).bytes);
    } finally {
      wipe(seed);
    }
  }

  /// Mirror of [signChallenge]: true only if [vaultId] is the hash of
  /// [publicKey] AND [signature] verifies over the challenge message.
  static Future<bool> verifyChallenge({
    required Uint8List publicKey,
    required String vaultId,
    required Uint8List nonce,
    required Uint8List signature,
    String purpose = authPurpose,
  }) async {
    if (publicKey.length != 32 || signature.length != 64) return false;
    if (nonce.length < nonceMin || nonce.length > nonceMax) return false;
    if (vaultIdFor(publicKey) != vaultId) return false;
    return _ed.verify(
      challengeMessage(vaultId, nonce, purpose: purpose),
      signature: Signature(signature,
          publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519)),
    );
  }

  static void _checkNonce(Uint8List nonce) {
    if (nonce.length < nonceMin || nonce.length > nonceMax) {
      throw const SsbCryptoException('bad nonce');
    }
  }

  /// An empty or all-zero key is a wiped keyring, not an owner (red team
  /// 2026-10-20, B6): refused rather than turned into one fixed identity.
  static Future<Uint8List> _seed(Uint8List vaultKey) {
    if (vaultKey.length != 32 || isAllZero(vaultKey)) {
      throw const SsbCryptoException('bad owner key');
    }
    return hkdfSha384(ikm: vaultKey, salt: const [], info: seedInfo, length: 32);
  }
}
