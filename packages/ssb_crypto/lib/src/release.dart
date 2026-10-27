import 'dart:typed_data';

import 'bytes.dart';
import 'hpke.dart';
import 'kit_code.dart';
import 'shamir.dart';
import 'vault.dart';
import 'xwing.dart';

/// Two-key release (spec §6.3). For each beneficiary and tier, the tier key
/// is split 2-of-3:
///
///   S1  printed Beneficiary Kit, handed over at enrollment
///   S2  HPKE-sealed to the beneficiary's X-Wing key and stored on the
///       server, which withholds it until the release timer expires.
///       The server cannot read it.
///   S3  optional printed kit for an attorney / safe-deposit box, so the
///       vault still opens if So Smart Apps no longer exists.
///
/// No single party (server, beneficiary, attorney) can recover the tier key.
///
/// Format v2 (SSB-2026-002, design D3/D10): every share carries the tier's
/// key-generation [epoch] (see `Share`), the S2 HPKE info binds it too, and
/// the kit labels are `SSB2-BK` / `SSB2-AK`. A kit cut before a rotation can
/// therefore be told apart from the current generation at recovery time
/// instead of silently yielding a revoked key. Version-1 kits (`SSB1-BK`,
/// 43-byte shares) are recovered only through `ReleaseV1` in
/// `package:ssb_crypto/legacy_v1.dart`.
class ReleaseBundle {
  final String beneficiaryKitCode; // S1
  final Uint8List sealedServerShare; // S2 (store on server)
  final String attorneyKitCode; // S3

  /// The key generation these three shares belong to.
  final int epoch;
  ReleaseBundle(this.beneficiaryKitCode, this.sealedServerShare, this.attorneyKitCode,
      {required this.epoch});
}

/// What the recovery paths return: the tier key and the generation it is.
typedef RecoveredTierKey = ({Uint8List key, int epoch});

abstract final class Release {
  static const s1Label = 'SSB2-BK';
  static const s3Label = 'SSB2-AK';
  static const _shareLen = Share.headerLength + tierKeyLength; // 61

  /// The only tier-key length the kit codes can carry back ([_shareLen]).
  static const tierKeyLength = 32;

  /// Error raised when S1 and the other share come from different key
  /// generations (a kit printed before a rotation). Distinct from the
  /// generic `decrypt failed` so the UI can say what to do: get a new kit.
  static const olderGeneration = 'kit from an older key generation';

  /// HPKE info for S2: label || len-prefixed vaultId || len-prefixed
  /// beneficiaryId || len-prefixed tier || u16be(epoch). Length prefixes
  /// make the encoding injective (ids containing delimiters cannot collide);
  /// the epoch (2 bytes, matching the share) binds the generation. Public so
  /// tests can open an S2 independently.
  static List<int> s2Info(String vaultId, String beneficiaryId, Tier t, {required int epoch}) =>
      concatBytes([
        utf8Bytes('ssb/v2/s2'),
        lengthPrefixed(vaultId),
        lengthPrefixed(beneficiaryId),
        lengthPrefixed(t.name),
        u16be(epoch),
      ]);

  static void _checkEpoch(int epoch) {
    if (epoch < 0 || epoch > Share.maxEpoch) {
      throw const SsbCryptoException('bad epoch');
    }
  }

  /// Splits [tierKey] (the key of [tier] at generation [epoch]) for one
  /// beneficiary.
  static Future<ReleaseBundle> create({
    required String vaultId,
    required String beneficiaryId,
    required Tier tier,
    required Uint8List tierKey,
    required Uint8List beneficiaryPublicKey,
    required int epoch,
  }) async {
    // Refuse before a single share exists (red team 2026-10-20):
    //  B3  a tier key that is all zeros is a wiped buffer, and one that is not
    //      32 bytes would split fine but never decode from a printed kit;
    //  B1  a zero / zero-half beneficiary key would leave S2 readable by the
    //      server, the one party the split exists to keep out.
    if (tierKey.length != tierKeyLength || isAllZero(tierKey)) {
      throw const SsbCryptoException('bad tier key');
    }
    _checkEpoch(epoch);
    // Copy before the first await (red team 2026-10-26): the key is used for
    // Hpke.seal only after Shamir.split has yielded, and a caller buffer
    // wiped in between must not turn the whole create() into an error (or,
    // before Hpke validated again, into a seal to a zero key).
    final recipientPk = Uint8List.fromList(beneficiaryPublicKey);
    XWing.validatePublicKey(recipientPk);
    // Shamir.split snapshots the secret itself; the explicit copy here keeps
    // this function correct even if that ever changes.
    final tk = Uint8List.fromList(tierKey);
    final List<Share> shares;
    try {
      shares = await Shamir.split(tk, shares: 3, threshold: 2, epoch: epoch);
    } finally {
      wipe(tk);
    }
    final s1 = shares[0].toBytes(), s2 = shares[1].toBytes(), s3 = shares[2].toBytes();
    try {
      return ReleaseBundle(
        await KitCode.encode(s1Label, s1),
        await Hpke.seal(recipientPk, s2,
            info: s2Info(vaultId, beneficiaryId, tier, epoch: epoch)),
        await KitCode.encode(s3Label, s3),
        epoch: epoch,
      );
    } finally {
      // Both the serialized copies and the Share objects they came from.
      wipe(s1);
      wipe(s2);
      wipe(s3);
      for (final s in shares) {
        s.erase();
      }
    }
  }

  /// The key generation a printed Beneficiary Kit belongs to, without any
  /// other share. Lets the app compare a kit against the server's current
  /// epoch ("outdated copy" vs "kit from an older generation", design D11)
  /// before asking for anything else.
  static Future<int> kitEpoch(String beneficiaryKitCode) async {
    final raw = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    try {
      return Share.fromBytes(raw).epoch;
    } finally {
      wipe(raw);
    }
  }

  /// Normal path: Beneficiary Kit (S1) + server share (S2) after the wait.
  ///
  /// [serverShareEpoch] is the generation the server reports for S2 (the
  /// `epoch` on the claim / tier document). When it is given and differs
  /// from the kit's epoch, the call fails with [olderGeneration] before S2
  /// is even opened. When it is omitted, S2 is opened under the kit's epoch
  /// and a generation mismatch surfaces as `decrypt failed` (the HPKE info
  /// binds the epoch). Either way the two decoded shares must agree.
  static Future<RecoveredTierKey> recoverWithServerShare({
    required String vaultId,
    required String beneficiaryId,
    required Tier tier,
    required String beneficiaryKitCode,
    required Uint8List sealedServerShare,
    required Uint8List beneficiarySecretKey,
    int? serverShareEpoch,
  }) async {
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw2;
    Share? s1, s2;
    try {
      s1 = Share.fromBytes(raw1);
      if (serverShareEpoch != null && serverShareEpoch != s1.epoch) {
        throw const SsbCryptoException(olderGeneration);
      }
      raw2 = await Hpke.open(beneficiarySecretKey, sealedServerShare,
          info: s2Info(vaultId, beneficiaryId, tier, epoch: s1.epoch));
      s2 = Share.fromBytes(raw2);
      if (s1.epoch != s2.epoch) throw const SsbCryptoException(olderGeneration);
      return (key: await Shamir.combine([s1, s2]), epoch: s1.epoch);
    } finally {
      // Decoded shares are wiped on every exit, including a failed combine.
      wipe(raw1);
      wipe(raw2);
      s1?.erase();
      s2?.erase();
    }
  }

  /// Company-gone path: Beneficiary Kit (S1) + attorney kit (S3), fully
  /// offline (this is what the open-source recovery tool runs).
  static Future<RecoveredTierKey> recoverOffline({
    required String beneficiaryKitCode,
    required String attorneyKitCode,
  }) async {
    final raw1 = await KitCode.decode(s1Label, beneficiaryKitCode, payloadLength: _shareLen);
    Uint8List? raw3;
    Share? s1, s3;
    try {
      s1 = Share.fromBytes(raw1);
      raw3 = await KitCode.decode(s3Label, attorneyKitCode, payloadLength: _shareLen);
      s3 = Share.fromBytes(raw3);
      if (s1.epoch != s3.epoch) throw const SsbCryptoException(olderGeneration);
      return (key: await Shamir.combine([s1, s3]), epoch: s1.epoch);
    } finally {
      wipe(raw1);
      wipe(raw3);
      s1?.erase();
      s3?.erase();
    }
  }
}
